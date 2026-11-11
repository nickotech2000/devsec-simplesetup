/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

using System.Buffers;
using System.Globalization;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;

sealed class HttpError(int code, string text) : Exception(text) { public int Code { get; } = code; }

// Counters instead of logs; shown by --status.
static class Stats
{
    public static long Requests, Hits, Misses, Stale, Rejected, Errors, Active, DnsLocal, DnsForwarded;
    public static readonly DateTime Started = DateTime.UtcNow;

    public static string Text() =>
        $"uptime {(DateTime.UtcNow - Started):d\\.hh\\:mm\\:ss}\nactive {Interlocked.Read(ref Active)}\nrequests {Interlocked.Read(ref Requests)}\n" +
        $"cache-hit {Interlocked.Read(ref Hits)}\ncache-miss {Interlocked.Read(ref Misses)}\ncache-stale {Interlocked.Read(ref Stale)}\n" +
        $"rejected {Interlocked.Read(ref Rejected)}\nerrors {Interlocked.Read(ref Errors)}" +
        (DnsServer.Running ? $"\ndns-local {Interlocked.Read(ref DnsLocal)}\ndns-forwarded {Interlocked.Read(ref DnsForwarded)}" : "");
}

sealed class Head
{
    public string A = "", B = "", C = "";       // request: method target version; response: version status reason
    public List<KeyValuePair<string, string>> H = new();
    public byte[] Raw = [];

    public string? Get(string name)
    {
        foreach (var kv in H) if (kv.Key.Equals(name, StringComparison.OrdinalIgnoreCase)) return kv.Value;
        return null;
    }

    public bool Has(string name) => Get(name) != null;

    // -1 when absent. Several Content-Length headers must agree (request smuggling guard).
    public long ContentLength()
    {
        long found = -1;
        foreach (var kv in H)
        {
            if (!kv.Key.Equals("Content-Length", StringComparison.OrdinalIgnoreCase)) continue;
            if (kv.Value.Length == 0 || kv.Value.Length > 10 || !kv.Value.All(char.IsAsciiDigit)) throw new HttpError(400, "Bad Request");
            long v = long.Parse(kv.Value, CultureInfo.InvariantCulture);
            if (found >= 0 && found != v) throw new HttpError(400, "Bad Request");
            found = v;
        }
        return found;
    }
}

// Small buffered reader over a stream; the 8 KB buffer is pooled.
sealed class Rdr(Stream s) : IDisposable
{
    public const int HeadMax = 8192;
    public byte[] B = ArrayPool<byte>.Shared.Rent(HeadMax);
    public int P, E;

    public void Dispose()
    {
        if (B.Length > 0) ArrayPool<byte>.Shared.Return(B);
        B = [];
    }

    async ValueTask<bool> More(CancellationToken ct)
    {
        if (E == B.Length)
        {
            if (P == 0) return false;
            Buffer.BlockCopy(B, P, B, 0, E - P);
            E -= P; P = 0;
        }
        int n = await s.ReadAsync(B.AsMemory(E), ct);
        if (n == 0) return false;
        E += n;
        return true;
    }

    public async Task<Head?> ReadHead(CancellationToken ct)
    {
        int rel = 0;
        while (true)
        {
            int from = P + rel;
            int idx = from <= E ? B.AsSpan(from, E - from).IndexOf("\r\n\r\n"u8) : -1;
            if (idx >= 0)
            {
                idx += from;
                int len = idx + 4 - P;
                if (len > HeadMax) throw new HttpError(431, "Request Header Fields Too Large");
                var h = Parse(B.AsSpan(P, idx - P));
                h.Raw = B.AsSpan(P, len).ToArray();
                P = idx + 4;
                return h;
            }
            if (E - P >= HeadMax) throw new HttpError(431, "Request Header Fields Too Large");
            rel = Math.Max(0, E - P - 3);
            if (!await More(ct))
            {
                if (E == P) return null;
                throw new HttpError(400, "Bad Request");
            }
        }
    }

    static Head Parse(ReadOnlySpan<byte> span)
    {
        var text = Encoding.Latin1.GetString(span);
        var lines = text.Split("\r\n");
        foreach (var ln in lines) if (ln.Contains('\n') || ln.Contains('\r') || ln.Contains('\0')) throw new HttpError(400, "Bad Request");
        var first = lines[0].Split(' ', 3);
        if (first.Length < 2 || first[0].Length == 0 || first[1].Length == 0) throw new HttpError(400, "Bad Request");
        var h = new Head { A = first[0], B = first[1], C = first.Length > 2 ? first[2] : "" };
        for (int i = 1; i < lines.Length; i++)
        {
            var ln = lines[i];
            int c = ln.IndexOf(':');
            if (c <= 0 || ln[0] == ' ' || ln[0] == '\t') throw new HttpError(400, "Bad Request");
            var name = ln[..c];
            foreach (var ch in name) if (ch <= ' ' || ch >= 0x7f) throw new HttpError(400, "Bad Request");
            h.H.Add(new(name, ln[(c + 1)..].Trim(' ', '\t')));
        }
        return h;
    }

    public async Task<byte[]> ReadBytes(int n, CancellationToken ct)
    {
        var r = new byte[n];
        int have = Math.Min(n, E - P);
        Buffer.BlockCopy(B, P, r, 0, have);
        P += have;
        while (have < n)
        {
            int k = await s.ReadAsync(r.AsMemory(have), ct);
            if (k == 0) throw new HttpError(400, "Bad Request");
            have += k;
        }
        return r;
    }

    async Task<string> ReadLine(CancellationToken ct)
    {
        while (true)
        {
            int i = B.AsSpan(P, E - P).IndexOf((byte)'\n');
            if (i >= 0)
            {
                var line = Encoding.Latin1.GetString(B, P, i).TrimEnd('\r');
                P += i + 1;
                return line;
            }
            if (E - P >= 256 || !await More(ct)) throw new HttpError(502, "Bad Gateway");
        }
    }

    // Upstream response body (chunked, Content-Length or until close). Null when it is larger than max.
    public async Task<byte[]?> ReadResponseBody(Head h, int max, CancellationToken ct)
    {
        var te = h.Get("Transfer-Encoding");
        if (te != null && te.Contains("chunked", StringComparison.OrdinalIgnoreCase))
        {
            using var ms = new MemoryStream();
            while (true)
            {
                var l = await ReadLine(ct);
                int sc = l.IndexOf(';');
                if (sc >= 0) l = l[..sc];
                if (!int.TryParse(l.Trim(), NumberStyles.HexNumber, CultureInfo.InvariantCulture, out int size) || size < 0) return null;
                if (size == 0) break;
                if (ms.Length + size > max) return null;
                ms.Write(await ReadBytes(size, ct));
                await ReadLine(ct);
            }
            return ms.ToArray();
        }
        long cl = h.ContentLength();
        if (cl >= 0) return cl > max ? null : await ReadBytes((int)cl, ct);

        using var all = new MemoryStream();
        while (true)
        {
            all.Write(B, P, E - P);
            P = E = 0;
            if (all.Length > max) return null;
            if (!await More(ct)) break;
        }
        return all.ToArray();
    }
}

static class Net
{

    // "host", "host:port" or "[v6]:port"
    public static (string Host, int Port) Authority(string s, int defPort)
    {
        string host;
        int port = defPort;
        s = s.Trim();
        if (s.StartsWith('['))
        {
            int e = s.IndexOf(']');
            if (e < 0) throw new HttpError(400, "Bad Request");
            host = s[1..e];
            var rest = s[(e + 1)..];
            if (rest.StartsWith(':')) port = ParsePort(rest[1..]);
        }
        else
        {
            int i = s.LastIndexOf(':');
            if (i >= 0) { host = s[..i]; port = ParsePort(s[(i + 1)..]); }
            else host = s;
        }
        if (host.Length == 0 || host.Any(c => c <= ' ' || c == '/' || c == '\\')) throw new HttpError(400, "Bad Request");
        return (host.ToLowerInvariant().TrimEnd('.'), port);
    }

    static int ParsePort(string p) =>
        int.TryParse(p, NumberStyles.None, CultureInfo.InvariantCulture, out int v) && v is > 0 and < 65536 ? v : throw new HttpError(400, "Bad Request");

    public static bool IsPrivate(IPAddress a)
    {
        if (a.IsIPv4MappedToIPv6) a = a.MapToIPv4();
        if (IPAddress.IsLoopback(a)) return true;
        var b = a.GetAddressBytes();
        if (a.AddressFamily == AddressFamily.InterNetwork)
            return b[0] == 0 || b[0] == 10 || b[0] >= 224 || (b[0] == 100 && b[1] is >= 64 and <= 127) || (b[0] == 169 && b[1] == 254) ||
                   (b[0] == 172 && b[1] is >= 16 and <= 31) || (b[0] == 192 && b[1] == 168) || (b[0] == 192 && b[1] == 0 && b[2] == 0);
        if (a.AddressFamily == AddressFamily.InterNetworkV6)
            return a.IsIPv6LinkLocal || a.IsIPv6SiteLocal || a.IsIPv6Multicast || a.Equals(IPAddress.IPv6Any) || (b[0] & 0xFE) == 0xFC;
        return true;
    }

    // Resolves and connects. The address that is checked is the address that is used (no DNS rebinding gap).
    public static async Task<Socket> Dial(string host, int port, bool blockPrivate, CancellationToken ct)
    {
        IPAddress[] addrs;
        try { addrs = IPAddress.TryParse(host, out var lit) ? [lit] : await Dns.GetHostAddressesAsync(host, ct); }
        catch { throw new HttpError(502, "Bad Gateway"); }
        bool tried = false;
        foreach (var a in addrs)
        {
            if (blockPrivate && IsPrivate(a)) continue;
            tried = true;
            var s = new Socket(a.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                using var t = CancellationTokenSource.CreateLinkedTokenSource(ct);
                t.CancelAfter(5000);
                await s.ConnectAsync(new IPEndPoint(a, port), t.Token);
                return s;
            }
            catch { s.Dispose(); }
        }
        throw tried || addrs.Length == 0 ? new HttpError(502, "Bad Gateway") : new HttpError(403, "Forbidden");
    }

    // Takes ownership of the socket. TLS 1.2+, normal certificate validation; revocation is off on purpose (the PKI proxy must not depend on itself).
    public static async Task<SslStream> Tls(Socket s, string host, CancellationToken ct)
    {
        var ssl = new SslStream(new NetworkStream(s, true), false);
        try
        {
            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
            {
                TargetHost = host,
                EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                CertificateRevocationCheckMode = X509RevocationMode.NoCheck,
            }, ct);
            return ssl;
        }
        catch { ssl.Dispose(); throw new HttpError(502, "Bad Gateway"); }
    }

    public static async Task Reply(Stream s, int code, string reason, string extra = "")
    {
        var b = Encoding.Latin1.GetBytes($"HTTP/1.1 {code} {reason}\r\nContent-Length: 0\r\nConnection: close\r\n{extra}\r\n");
        await s.WriteAsync(b);
    }

    public static byte[] BuildRequest(string method, string path, string hostHeader, Head? src, Func<string, bool>? keep, byte[]? body)
    {
        var sb = new StringBuilder();
        sb.Append(method).Append(' ').Append(path).Append(" HTTP/1.1\r\nHost: ").Append(hostHeader).Append("\r\nConnection: close\r\n");
        if (src != null && keep != null)
            foreach (var kv in src.H) if (keep(kv.Key)) sb.Append(kv.Key).Append(": ").Append(kv.Value).Append("\r\n");
        if (body != null) sb.Append("Content-Length: ").Append(body.Length).Append("\r\n");
        sb.Append("\r\n");
        var head = Encoding.Latin1.GetBytes(sb.ToString());
        if (body == null || body.Length == 0) return head;
        var all = new byte[head.Length + body.Length];
        head.CopyTo(all, 0);
        body.CopyTo(all, head.Length);
        return all;
    }

    // Raw copy until EOF; the idle timer is re-armed on every chunk.
    public static async Task Relay(Stream from, Stream to, CancellationTokenSource cts, int idleMs)
    {
        var buf = ArrayPool<byte>.Shared.Rent(8192);
        try
        {
            cts.CancelAfter(idleMs);
            int n;
            while ((n = await from.ReadAsync(buf, cts.Token)) > 0)
            {
                await to.WriteAsync(buf.AsMemory(0, n), cts.Token);
                cts.CancelAfter(idleMs);
            }
        }
        catch { }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }

    // Two-way TCP pump with an idle timeout; used by CONNECT tunnels and tcp listeners.
    public static async Task Pump(Socket a, Socket b, int idleSeconds, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        int idle = idleSeconds * 1000;
        cts.CancelAfter(idle);
        using var sa = new NetworkStream(a, false);
        using var sb = new NetworkStream(b, false);
        await Task.WhenAll(Copy(sa, sb, b, cts, idle), Copy(sb, sa, a, cts, idle));
    }

    static async Task Copy(Stream from, Stream to, Socket toSock, CancellationTokenSource cts, int idle)
    {
        var buf = ArrayPool<byte>.Shared.Rent(16384);
        try
        {
            while (true)
            {
                int n = await from.ReadAsync(buf, cts.Token);
                if (n == 0) { try { toSock.Shutdown(SocketShutdown.Send); } catch { } break; }
                await to.WriteAsync(buf.AsMemory(0, n), cts.Token);
                cts.CancelAfter(idle);
            }
        }
        catch { cts.Cancel(); }
        finally { ArrayPool<byte>.Shared.Return(buf); }
    }
}
