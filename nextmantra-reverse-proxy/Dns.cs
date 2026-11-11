/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

// audit:allow-file(raw-socket-shell) a proxy and DNS server is a network program: it opens sockets by design (listeners, outbound upstream connections)

using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;

// ===== tiny local DNS server (--mode full) =====
// Answers A queries for the names listed in appsettings.json (one by one, no wildcards).
// Every other name is forwarded, unchanged, to the DNS servers the operating system already uses.
// Listens on loopback only, so it is never an open resolver. It does not change any OS setting by itself.
static class DnsServer
{
    static readonly List<UdpClient> udps = new();
    static readonly List<TcpListener> tcps = new();
    static readonly HashSet<IPAddress> selfAddrs = new();   // every address this server answers on: never forward to these
    static CancellationTokenSource? cts;
    static DnsRuntime cfg = new();
    static readonly object upLock = new();
    static IPEndPoint[] upCache = [];
    static DateTime upStamp = DateTime.MinValue;

    public static bool Running => cts != null;

    public static void Start(DnsRuntime c)
    {
        Stop();
        cfg = c;
        cts = new CancellationTokenSource();
        try { Open(c.Bind); }
        catch { Stop(); throw; }
    }

    // Linux: the helper link gets its own address (see OsRouting); the server answers there as well.
    public static void AddListener(IPEndPoint ep) { if (cts != null) Open(ep); }

    static void Open(IPEndPoint ep)
    {
        var u = new UdpClient(new IPEndPoint(ep.Address, ep.Port));
        TcpListener t;
        try { t = new TcpListener(ep); t.Start(64); }
        catch { u.Dispose(); throw; }
        lock (upLock) { udps.Add(u); tcps.Add(t); selfAddrs.Add(ep.Address); upStamp = DateTime.MinValue; }
        _ = UdpLoop(u, cts!.Token);
        _ = TcpLoop(t, cts.Token);
    }

    public static void Stop()
    {
        try { cts?.Cancel(); } catch { }
        lock (upLock)
        {
            foreach (var u in udps) { try { u.Dispose(); } catch { } }
            foreach (var t in tcps) { try { t.Stop(); } catch { } }
            udps.Clear(); tcps.Clear(); selfAddrs.Clear();
        }
        cts = null;
    }

    // ----- transport -----
    static async Task UdpLoop(UdpClient u, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult r;
            try { r = await u.ReceiveAsync(ct); }
            catch when (ct.IsCancellationRequested) { return; }
            catch (SocketException) { continue; }   // e.g. ICMP port unreachable echoed back on Windows
            catch (ObjectDisposedException) { return; }
            var from = r.RemoteEndPoint;
            var data = r.Buffer;
            _ = Task.Run(async () =>
            {
                try
                {
                    var reply = await Answer(data, false);
                    if (reply != null) await u.SendAsync(reply, reply.Length, from);
                }
                catch { Interlocked.Increment(ref Stats.Errors); }
            });
        }
    }

    static async Task TcpLoop(TcpListener t, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            Socket c;
            try { c = await t.AcceptSocketAsync(ct); }
            catch when (ct.IsCancellationRequested) { return; }
            catch (ObjectDisposedException) { return; }
            catch { await Task.Delay(50); continue; }
            _ = Task.Run(async () =>
            {
                try
                {
                    using (c)
                    using (var ns = new NetworkStream(c, false))
                    using (var to = CancellationTokenSource.CreateLinkedTokenSource(ct))
                    {
                        to.CancelAfter(5000);
                        var len = new byte[2];
                        if (!await ReadFull(ns, len, to.Token)) return;
                        int n = (len[0] << 8) | len[1];
                        if (n < 12 || n > 4096) return;
                        var q = new byte[n];
                        if (!await ReadFull(ns, q, to.Token)) return;
                        var reply = await Answer(q, true);
                        if (reply == null) return;
                        var o = new byte[reply.Length + 2];
                        o[0] = (byte)(reply.Length >> 8); o[1] = (byte)reply.Length;
                        Buffer.BlockCopy(reply, 0, o, 2, reply.Length);
                        await ns.WriteAsync(o, to.Token);
                    }
                }
                catch { }
            });
        }
    }

    static async Task<bool> ReadFull(Stream s, byte[] buf, CancellationToken ct)
    {
        int n = 0;
        while (n < buf.Length)
        {
            int r = await s.ReadAsync(buf.AsMemory(n), ct);
            if (r == 0) return false;
            n += r;
        }
        return true;
    }

    // ----- one query -----
    // Returns the reply bytes, or null when the query is garbage and should be dropped.
    static async Task<byte[]?> Answer(byte[] q, bool viaTcp)
    {
        if (!DnsWire.TryParse(q, out var m)) return null;
        if ((q[2] & 0x80) != 0) return null;                                  // a response, not a query
        if (((q[2] >> 3) & 0x0F) != 0) return DnsWire.Error(q, m.QuestionEnd, 4);   // opcode other than QUERY: NOTIMP
        if (m.QdCount != 1) return DnsWire.Error(q, m.QuestionEnd, 1);        // FORMERR

        string name = m.Name.ToLowerInvariant().TrimEnd('.');
        if (cfg.Names.TryGetValue(name, out var ip))
        {
            Interlocked.Increment(ref Stats.DnsLocal);
            // A gets the address; AAAA and everything else gets NODATA, so IPv6 clients do not wait for a name that has no IPv6.
            if (m.QType == 1 && m.QClass == 1) return DnsWire.AnswerA(q, m.QuestionEnd, ip, cfg.Ttl);
            return DnsWire.Error(q, m.QuestionEnd, 0);
        }

        Interlocked.Increment(ref Stats.DnsForwarded);
        var fwd = await Forward(q, viaTcp);
        return fwd ?? DnsWire.Error(q, m.QuestionEnd, 2);   // SERVFAIL when no upstream answered
    }

    // ----- forwarding to the OS resolvers -----
    static async Task<byte[]?> Forward(byte[] q, bool viaTcp)
    {
        foreach (var up in Upstreams())
        {
            try
            {
                var r = viaTcp ? await ForwardTcp(q, up) : await ForwardUdp(q, up);
                if (r != null) return r;
            }
            catch { }
        }
        return null;
    }

    static async Task<byte[]?> ForwardUdp(byte[] q, IPEndPoint up)
    {
        using var c = new UdpClient(up.AddressFamily);
        using var to = new CancellationTokenSource(2000);
        await c.SendAsync(q, q.Length, up);
        while (true)
        {
            var r = await c.ReceiveAsync(to.Token);
            if (r.Buffer.Length >= 12 && r.Buffer[0] == q[0] && r.Buffer[1] == q[1]) return r.Buffer;   // ignore stray packets
        }
    }

    static async Task<byte[]?> ForwardTcp(byte[] q, IPEndPoint up)
    {
        using var to = new CancellationTokenSource(3000);
        using var c = new TcpClient(up.AddressFamily);
        await c.ConnectAsync(up, to.Token);
        using var ns = c.GetStream();
        var o = new byte[q.Length + 2];
        o[0] = (byte)(q.Length >> 8); o[1] = (byte)q.Length;
        Buffer.BlockCopy(q, 0, o, 2, q.Length);
        await ns.WriteAsync(o, to.Token);
        var len = new byte[2];
        if (!await ReadFull(ns, len, to.Token)) return null;
        var r = new byte[(len[0] << 8) | len[1]];
        if (r.Length < 12 || !await ReadFull(ns, r, to.Token)) return null;
        return r;
    }

    // Servers the OS uses today, read fresh every 20 seconds so a VPN connect or a Wi-Fi change is followed.
    // Our own address is left out, so the server can never forward to itself.
    public static IPEndPoint[] Upstreams()
    {
        if (cfg.Upstream.Length > 0) return cfg.Upstream;
        lock (upLock)
        {
            if ((DateTime.UtcNow - upStamp).TotalSeconds < 20 && upCache.Length > 0) return upCache.Where(e => !selfAddrs.Contains(e.Address)).ToArray();
            var list = OsResolvers(selfAddrs.Count > 0 ? selfAddrs.ToArray() : [cfg.Bind.Address]);
            upCache = list; upStamp = DateTime.UtcNow;
            return list;
        }
    }

    public static IPEndPoint[] OsResolvers(IPAddress[] self)
    {
        var found = new List<IPAddress>();
        try
        {
            if (OperatingSystem.IsLinux())
            {
                // systemd-resolved keeps the real upstream servers here; /etc/resolv.conf then only holds its 127.0.0.53 stub.
                foreach (var f in new[] { "/run/systemd/resolve/resolv.conf", "/etc/resolv.conf" })
                {
                    if (!File.Exists(f)) continue;
                    foreach (var line in File.ReadLines(f))
                    {
                        var p = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
                        if (p.Length >= 2 && p[0] == "nameserver" && IPAddress.TryParse(p[1].Split('%')[0], out var a)) found.Add(a);
                    }
                    if (found.Any(a => !IPAddress.IsLoopback(a))) break;
                }
            }
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                foreach (var a in nic.GetIPProperties().DnsAddresses) found.Add(a);
            }
        }
        catch { }
        return found
            .Where(a => !self.Contains(a) && !a.Equals(IPAddress.Any) && !a.Equals(IPAddress.IPv6Any) && !(a.IsIPv6SiteLocal))
            .Where(a => !(a.AddressFamily == AddressFamily.InterNetworkV6 && a.IsIPv6LinkLocal))   // needs a scope id; skip, IPv4 servers are always present too
            .Distinct().Select(a => new IPEndPoint(a, 53)).ToArray();
    }
}

// ===== DNS message helpers =====
readonly record struct DnsMessage(int QdCount, string Name, int QType, int QClass, int QuestionEnd);

static class DnsWire
{
    // Parses the header and the first question only.
    public static bool TryParse(byte[] q, out DnsMessage m)
    {
        m = default;
        if (q.Length < 12) return false;
        int qd = (q[4] << 8) | q[5];
        if (qd == 0) { m = new DnsMessage(0, "", 0, 0, 12); return true; }
        int pos = 12;
        var sb = new System.Text.StringBuilder();
        int guard = 0;
        while (true)
        {
            if (pos >= q.Length || guard++ > 64) return false;
            int len = q[pos];
            if (len == 0) { pos++; break; }
            if ((len & 0xC0) != 0) return false;   // compression pointers do not occur in a query's first question
            if (pos + 1 + len > q.Length) return false;
            if (sb.Length > 0) sb.Append('.');
            for (int i = 0; i < len; i++) sb.Append((char)q[pos + 1 + i]);
            pos += 1 + len;
        }
        if (pos + 4 > q.Length) return false;
        int type = (q[pos] << 8) | q[pos + 1];
        int cls = (q[pos + 2] << 8) | q[pos + 3];
        m = new DnsMessage(qd, sb.ToString(), type, cls, pos + 4);
        return true;
    }

    // Header + echoed question + no answer, with the given RCODE (0 = NOERROR/NODATA, 1 = FORMERR, 2 = SERVFAIL, 3 = NXDOMAIN, 4 = NOTIMP).
    public static byte[] Error(byte[] q, int qEnd, int rcode)
    {
        int end = Math.Min(qEnd, q.Length);
        var r = new byte[end];
        Buffer.BlockCopy(q, 0, r, 0, end);
        Header(r, rcode, 0, end > 12);
        return r;
    }

    public static byte[] AnswerA(byte[] q, int qEnd, IPAddress ip, int ttl)
    {
        var b = ip.GetAddressBytes();
        var r = new byte[qEnd + 16];
        Buffer.BlockCopy(q, 0, r, 0, qEnd);
        Header(r, 0, 1, true);
        int p = qEnd;
        r[p++] = 0xC0; r[p++] = 0x0C;                 // name: pointer to the question
        r[p++] = 0; r[p++] = 1;                       // type A
        r[p++] = 0; r[p++] = 1;                       // class IN
        r[p++] = (byte)(ttl >> 24); r[p++] = (byte)(ttl >> 16); r[p++] = (byte)(ttl >> 8); r[p++] = (byte)ttl;
        r[p++] = 0; r[p++] = 4;
        Buffer.BlockCopy(b, 0, r, p, 4);
        return r;
    }

    static void Header(byte[] r, int rcode, int answers, bool hasQuestion)
    {
        byte rd = (byte)(r[2] & 0x01);
        r[2] = (byte)(0x80 | 0x04 | rd);              // QR, AA, keep RD
        r[3] = (byte)(0x80 | (rcode & 0x0F));         // RA + RCODE
        r[4] = 0; r[5] = (byte)(hasQuestion ? 1 : 0);
        r[6] = (byte)(answers >> 8); r[7] = (byte)answers;
        r[8] = r[9] = r[10] = r[11] = 0;
    }

    // Query builder for --dns-test.
    public static byte[] BuildQuery(string name, int type, ushort id)
    {
        var ms = new MemoryStream();
        ms.Write([(byte)(id >> 8), (byte)id, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
        foreach (var label in name.TrimEnd('.').Split('.'))
        {
            var lb = System.Text.Encoding.ASCII.GetBytes(label);
            ms.WriteByte((byte)lb.Length); ms.Write(lb);
        }
        ms.WriteByte(0);
        ms.Write([(byte)(type >> 8), (byte)type, 0, 1]);
        return ms.ToArray();
    }

    // First A record of a reply, or null.
    public static (int Rcode, IPAddress? A) ReadReply(byte[] r)
    {
        if (r.Length < 12) return (-1, null);
        int rcode = r[3] & 0x0F, an = (r[6] << 8) | r[7];
        int pos = 12;
        for (int i = 0; i < (r[4] << 8 | r[5]); i++)
        {
            pos = SkipName(r, pos);
            if (pos < 0) return (rcode, null);
            pos += 4;
        }
        for (int i = 0; i < an; i++)
        {
            pos = SkipName(r, pos);
            if (pos < 0 || pos + 10 > r.Length) return (rcode, null);
            int type = (r[pos] << 8) | r[pos + 1], rdlen = (r[pos + 8] << 8) | r[pos + 9];
            pos += 10;
            if (type == 1 && rdlen == 4 && pos + 4 <= r.Length) return (rcode, new IPAddress(r.AsSpan(pos, 4)));
            pos += rdlen;
        }
        return (rcode, null);
    }

    static int SkipName(byte[] r, int pos)
    {
        while (pos < r.Length)
        {
            int len = r[pos];
            if (len == 0) return pos + 1;
            if ((len & 0xC0) == 0xC0) return pos + 2;
            pos += 1 + len;
        }
        return -1;
    }
}
