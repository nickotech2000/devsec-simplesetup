/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

using System.Collections.Concurrent;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;

static class Handlers
{
    static readonly byte[] Established = "HTTP/1.1 200 Connection Established\r\n\r\n"u8.ToArray();
    static readonly string[] ReverseHeaders = ["Accept", "Content-Type", "User-Agent", "If-None-Match", "If-Modified-Since"];
    static readonly string[] HopByHop = ["Connection", "Keep-Alive", "TE", "Trailer", "Transfer-Encoding", "Upgrade", "Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Host", "Content-Length"];
    static readonly string[] ForwardMethods = ["GET", "HEAD", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"];

    public static Task Run(Socket c, Listener l, CancellationToken ct) => l.Mode switch
    {
        "http-reverse" => Reverse(c, l, ct),
        "http-forward" => Forward(c, l, ct),
        _ => Tcp(c, l, ct),
    };

    static CancellationTokenSource Linked(CancellationToken ct, int ms)
    {
        var c = CancellationTokenSource.CreateLinkedTokenSource(ct);
        c.CancelAfter(ms);
        return c;
    }

    static string HostOf(string? hv)
    {
        if (hv == null) throw new HttpError(400, "Bad Request");
        hv = hv.Trim().ToLowerInvariant();
        int i = hv.LastIndexOf(':');
        if (i > 0 && !hv.EndsWith(']')) hv = hv[..i];
        return hv.TrimEnd('.');
    }

    // ===== http-reverse: <route host> -> https://<upstream> =====
    static async Task Reverse(Socket c, Listener l, CancellationToken ct)
    {
        using var cs = new NetworkStream(c, false);
        using var rd = new Rdr(cs);
        using var total = Linked(ct, 30000);
        try
        {
            Head? h;
            using (var hc = Linked(ct, 5000)) h = await rd.ReadHead(hc.Token);
            if (h == null) return;

            string method = h.A, path = h.B;
            if (method is not ("GET" or "HEAD" or "POST")) throw new HttpError(405, "Method Not Allowed");
            if (h.C is not ("HTTP/1.1" or "HTTP/1.0")) throw new HttpError(505, "HTTP Version Not Supported");
            if (path.Length > 2048 || path[0] != '/' || path.Any(ch => ch < 0x21 || ch > 0x7e)) throw new HttpError(400, "Bad Request");
            var host = HostOf(h.Get("Host"));
            if (!l.Routes.TryGetValue(host, out var up)) throw new HttpError(404, "Not Found");
            if (h.Has("Transfer-Encoding")) throw new HttpError(501, "Not Implemented");

            long cl = h.ContentLength();
            byte[]? body = null;
            if (method == "POST")
            {
                if (cl <= 0) throw new HttpError(411, "Length Required");
                if (cl > l.MaxBody) throw new HttpError(413, "Payload Too Large");
                var ctype = h.Get("Content-Type");
                if (ctype == null || !ctype.StartsWith("application/ocsp-request", StringComparison.OrdinalIgnoreCase)) throw new HttpError(415, "Unsupported Media Type");
                body = await rd.ReadBytes((int)cl, total.Token);
            }
            else if (cl > 0) throw new HttpError(400, "Bad Request");

            Interlocked.Increment(ref Stats.Requests);
            string hostHeader = up.Port == 443 ? up.Host : up.Host + ":" + up.Port;

            if (method != "POST" && Cache.Wants(path))
            {
                var (e, status) = await Cache.Get(host + path, () => Cache.Fetch(up.Host, up.Port, hostHeader, path));
                if (e == null) throw status == 404 ? new HttpError(404, "Not Found") : new HttpError(502, "Bad Gateway");
                long rem = Math.Clamp((e.Fresh - DateTime.UtcNow.Ticks) / TimeSpan.TicksPerSecond, 0, int.MaxValue);
                var head = Encoding.ASCII.GetBytes($"HTTP/1.1 200 OK\r\nContent-Type: {e.Type}\r\nContent-Length: {e.Body.Length}\r\nCache-Control: public, max-age={(rem == 0 ? 60 : rem)}\r\nConnection: close\r\n\r\n");
                await cs.WriteAsync(head, total.Token);
                if (method == "GET") await cs.WriteAsync(e.Body, total.Token);
                return;
            }

            Stream ssl;
            try
            {
                ssl = await Net.Tls(await Net.Dial(up.Host, up.Port, false, total.Token), up.Host, total.Token);
                var req = Net.BuildRequest(method, path, hostHeader, h, k => ReverseHeaders.Contains(k, StringComparer.OrdinalIgnoreCase), body);
                await ssl.WriteAsync(req, total.Token);
            }
            catch (HttpError) { throw; }
            catch { throw new HttpError(502, "Bad Gateway"); }
            using (ssl) await Net.Relay(ssl, cs, total, 15000);
        }
        catch (HttpError e)
        {
            Interlocked.Increment(ref Stats.Rejected);
            try { await Net.Reply(cs, e.Code, e.Message); } catch { }
        }
    }

    // ===== http-forward: absolute-URI proxying (http) and CONNECT tunnels, destination allowlist + SSRF guard =====
    static async Task Forward(Socket c, Listener l, CancellationToken ct)
    {
        using var cs = new NetworkStream(c, false);
        using var rd = new Rdr(cs);
        try
        {
            Head? h;
            using (var hc = Linked(ct, 5000)) h = await rd.ReadHead(hc.Token);
            if (h == null) return;
            if (h.C is not ("HTTP/1.1" or "HTTP/1.0")) throw new HttpError(505, "HTTP Version Not Supported");
            if (l.Token != null && !Authorized(h, l.Token))
            {
                Interlocked.Increment(ref Stats.Rejected);
                await Net.Reply(cs, 407, "Proxy Authentication Required", "Proxy-Authenticate: Basic realm=\"proxy\"\r\n");
                return;
            }
            Interlocked.Increment(ref Stats.Requests);

            if (h.A == "CONNECT")
            {
                var (host, port) = Net.Authority(h.B, 443);
                Allow(l, host, port);
                Socket up;
                using (var dc = Linked(ct, 8000)) up = await Net.Dial(host, port, !l.AllowPrivate, dc.Token);
                using (up)
                {
                    await cs.WriteAsync(Established, ct);
                    if (rd.E > rd.P)
                    {
                        using var us = new NetworkStream(up, false);
                        await us.WriteAsync(rd.B.AsMemory(rd.P, rd.E - rd.P), ct);
                    }
                    await Net.Pump(c, up, l.IdleSeconds, ct);
                }
                return;
            }

            if (!ForwardMethods.Contains(h.A)) throw new HttpError(405, "Method Not Allowed");
            if (!Uri.TryCreate(h.B, UriKind.Absolute, out var u) || u.Scheme != Uri.UriSchemeHttp || u.UserInfo.Length > 0) throw new HttpError(400, "Bad Request");
            string dest = u.DnsSafeHost.ToLowerInvariant().TrimEnd('.');
            Allow(l, dest, u.Port);
            if (h.Has("Transfer-Encoding")) throw new HttpError(501, "Not Implemented");
            long cl = h.ContentLength();
            if (cl > l.MaxBody) throw new HttpError(413, "Payload Too Large");

            using var total = Linked(ct, 30000);
            byte[]? body = cl > 0 ? await rd.ReadBytes((int)cl, total.Token) : null;
            Socket sock = await Net.Dial(dest, u.Port, !l.AllowPrivate, total.Token);
            using (sock)
            using (var ns = new NetworkStream(sock, false))
            {
                var req = Net.BuildRequest(h.A, u.PathAndQuery, u.Authority, h,
                    k => !HopByHop.Contains(k, StringComparer.OrdinalIgnoreCase) && !k.StartsWith("Proxy-", StringComparison.OrdinalIgnoreCase), body);
                await ns.WriteAsync(req, total.Token);
                await Net.Relay(ns, cs, total, l.IdleSeconds * 1000);
            }
        }
        catch (HttpError e)
        {
            Interlocked.Increment(ref Stats.Rejected);
            try { await Net.Reply(cs, e.Code, e.Message); } catch { }
        }
    }

    static void Allow(Listener l, string host, int port)
    {
        if (!l.PortOk(port) || !l.HostOk(host)) throw new HttpError(403, "Forbidden");
    }

    static bool Authorized(Head h, string token)
    {
        var v = h.Get("Proxy-Authorization");
        if (v == null) return false;
        string given;
        if (v.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) given = v[7..].Trim();
        else if (v.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        {
            try
            {
                var dec = Encoding.UTF8.GetString(Convert.FromBase64String(v[6..].Trim()));
                given = dec[(dec.IndexOf(':') + 1)..];
            }
            catch { return false; }
        }
        else return false;
        return CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(given), Encoding.UTF8.GetBytes(token));
    }

    // ===== tcp: fixed target =====
    static async Task Tcp(Socket c, Listener l, CancellationToken ct)
    {
        Socket up;
        try { using var dc = Linked(ct, 8000); up = await Net.Dial(l.TargetHost, l.TargetPort, false, dc.Token); }
        catch { Interlocked.Increment(ref Stats.Errors); return; }
        using (up)
        {
            Interlocked.Increment(ref Stats.Requests);
            await Net.Pump(c, up, l.IdleSeconds, ct);
        }
    }
}

// ===== CRL/CRT response cache: in memory, single-flight refresh, stale-if-error, optional snapshot on disk =====
sealed record Fetched(CacheEntry? E, int Status);

sealed class CacheEntry
{
    public byte[] Body = [];
    public string Type = "application/octet-stream";
    public long Fresh, Stale;   // UTC ticks
}

static class Cache
{
    static readonly object gate = new();
    static readonly Dictionary<string, CacheEntry> map = new();
    static readonly ConcurrentDictionary<string, Task<Fetched>> inflight = new();
    static CacheSettings cfg = new();
    static string[] exts = [".crl", ".crt"];
    static string? file;
    static long total;
    static bool inited;

    public static void Init(CacheSettings s)
    {
        if (inited) return;
        inited = true;
        cfg = s;
        exts = (s.Extensions is { Length: > 0 } ? s.Extensions : [".crl", ".crt"]).Select(e => e.ToLowerInvariant()).ToArray();
        if (!s.Enabled) return;
        file = s.Path ?? (OperatingSystem.IsWindows()
            ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "pkiproxy", "cache.bin")
            : "/var/lib/pkiproxy/cache.bin");
        Load();
    }

    public static bool Wants(string path)
    {
        if (!cfg.Enabled) return false;
        int q = path.IndexOf('?');
        var p = (q >= 0 ? path[..q] : path).ToLowerInvariant();
        foreach (var e in exts) if (p.EndsWith(e, StringComparison.Ordinal)) return true;
        return false;
    }

    public static async Task<(CacheEntry? E, int Status)> Get(string key, Func<Task<Fetched>> fetch)
    {
        CacheEntry? e;
        lock (gate) map.TryGetValue(key, out e);
        long now = DateTime.UtcNow.Ticks;
        if (e != null && now < e.Fresh) { Interlocked.Increment(ref Stats.Hits); return (e, 200); }

        var r = await inflight.GetOrAdd(key, k => Refresh(k, fetch));
        if (r.E != null) { Interlocked.Increment(ref Stats.Misses); return (r.E, 200); }
        if (e != null && now < e.Stale) { Interlocked.Increment(ref Stats.Stale); return (e, 200); }
        return (null, r.Status);
    }

    static async Task<Fetched> Refresh(string key, Func<Task<Fetched>> fetch)
    {
        await Task.Yield();
        try
        {
            var r = await fetch();
            if (r.E != null) Store(key, r.E);
            return r;
        }
        finally { inflight.TryRemove(key, out _); }
    }

    static void Store(string key, CacheEntry e)
    {
        lock (gate)
        {
            if (map.TryGetValue(key, out var old)) total -= old.Body.Length;
            map[key] = e;
            total += e.Body.Length;
            while (total > cfg.MaxBytes && map.Count > 1)
            {
                var victim = map.Where(kv => kv.Value != e).OrderBy(kv => kv.Value.Fresh).First();
                total -= victim.Value.Body.Length;
                map.Remove(victim.Key);
            }
        }
        Save();
    }

    public static async Task<Fetched> Fetch(string host, int port, string hostHeader, string path)
    {
        using var cts = new CancellationTokenSource(15000);
        try
        {
            using var ssl = await Net.Tls(await Net.Dial(host, port, false, cts.Token), host, cts.Token);
            await ssl.WriteAsync(Net.BuildRequest("GET", path, hostHeader, null, null, null), cts.Token);
            using var rd = new Rdr(ssl);
            var h = await rd.ReadHead(cts.Token);
            if (h == null || !int.TryParse(h.B, out int status)) return new(null, 502);
            if (status != 200) return new(null, status);
            var body = await rd.ReadResponseBody(h, 1 << 20, cts.Token);
            if (body == null || body.Length == 0) return new(null, 502);

            int ttl = 21600;
            var cc = h.Get("Cache-Control");
            int m = cc == null ? -1 : cc.IndexOf("max-age=", StringComparison.OrdinalIgnoreCase);
            if (m >= 0)
            {
                var digits = new string(cc!.Skip(m + 8).TakeWhile(char.IsAsciiDigit).ToArray());
                if (int.TryParse(digits, out int v)) ttl = v;
            }
            ttl = Math.Clamp(ttl, cfg.MinTtlSeconds, cfg.MaxTtlSeconds);
            long now = DateTime.UtcNow.Ticks;
            return new(new CacheEntry
            {
                Body = body,
                Type = h.Get("Content-Type") ?? (path.Contains(".crl", StringComparison.OrdinalIgnoreCase) ? "application/pkix-crl" : "application/pkix-cert"),
                Fresh = now + ttl * TimeSpan.TicksPerSecond,
                Stale = now + (long)cfg.StaleSeconds * TimeSpan.TicksPerSecond,
            }, 200);
        }
        catch { return new(null, 502); }
    }

    static void Save()
    {
        if (file == null) return;
        try
        {
            Directory.CreateDirectory(Path.GetDirectoryName(file)!);
            var tmp = file + ".tmp";
            lock (gate)
            {
                using (var w = new BinaryWriter(File.Create(tmp)))
                {
                    w.Write("PKC1");
                    w.Write(map.Count);
                    foreach (var kv in map)
                    {
                        w.Write(kv.Key); w.Write(kv.Value.Type); w.Write(kv.Value.Fresh); w.Write(kv.Value.Stale);
                        w.Write(kv.Value.Body.Length); w.Write(kv.Value.Body);
                    }
                }
                File.Move(tmp, file, true);
            }
        }
        catch { }
    }

    static void Load()
    {
        try
        {
            if (file == null || !File.Exists(file)) return;
            using var r = new BinaryReader(File.OpenRead(file));
            if (r.ReadString() != "PKC1") return;
            int n = r.ReadInt32();
            long now = DateTime.UtcNow.Ticks;
            for (int i = 0; i < n; i++)
            {
                var key = r.ReadString();
                var e = new CacheEntry { Type = r.ReadString(), Fresh = r.ReadInt64(), Stale = r.ReadInt64() };
                int len = r.ReadInt32();
                if (len < 0 || len > (1 << 20)) return;
                e.Body = r.ReadBytes(len);
                if (now >= e.Stale) continue;
                map[key] = e;
                total += e.Body.Length;
            }
        }
        catch { map.Clear(); total = 0; }
    }
}
