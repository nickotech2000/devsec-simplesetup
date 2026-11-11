/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

// audit:allow-file(raw-socket-shell,hidden-window) a proxy and DNS server is a network program: it opens sockets by design (listeners, outbound upstream connections); --dns-test starts node/java/go with captured output (no console window of their own)

using System.ComponentModel;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

// ===== runs a short-lived tool (node, java, go ...) with a time limit; used by --dns-test and --env-report =====
static class Probe
{
    // Code -2: the tool is not installed. Code -3: it did not finish in time.
    public static (int Code, string Out) Run(string file, string[] args, int timeoutMs = 10000, string? workDir = null)
    {
        var psi = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        if (workDir != null) psi.WorkingDirectory = workDir;
        foreach (var x in args) psi.ArgumentList.Add(x);
        try
        {
            using var p = Process.Start(psi)!;
            var so = p.StandardOutput.ReadToEndAsync();
            var se = p.StandardError.ReadToEndAsync();
            if (!p.WaitForExit(timeoutMs))
            {
                try { p.Kill(true); } catch { }
                return (-3, "timed out after " + timeoutMs / 1000 + "s");
            }
            p.WaitForExit();
            return (p.ExitCode, (so.Result + se.Result).Trim());
        }
        catch (Win32Exception) { return (-2, "not installed"); }
        catch (Exception ex) { return (-1, ex.Message); }
    }
}

// ===== --dns-test: one PASS / FAIL / SKIP line per check =====
static class DnsTest
{
    static int pass, fail, skip;

    static void Line(string tag, string text)
    {
        Console.ForegroundColor = tag switch { "PASS" => ConsoleColor.Green, "FAIL" => ConsoleColor.Red, "SKIP" => ConsoleColor.DarkYellow, _ => ConsoleColor.Gray };
        Console.Write("  " + tag.PadRight(5));
        Console.ResetColor();
        Console.WriteLine(text);
        if (tag == "PASS") pass++; else if (tag == "FAIL") fail++; else if (tag == "SKIP") skip++;
    }

    public static int Run(Args a)
    {
        Program.Banner();
        Config cfg;
        try { cfg = Config.Load(Paths.Config(a)); }
        catch (Exception ex) { Console.Error.WriteLine("CONFIG ERROR: " + ex.Message); return 1; }

        var names = cfg.Dns.Names.Keys.OrderBy(n => n, StringComparer.Ordinal).ToList();
        var extra = a.Value("names");
        if (extra != null) foreach (var n in extra.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)) if (!names.Contains(n)) names.Add(n);
        Console.WriteLine($"Mode in the settings: {cfg.Mode}. Names under test: {string.Join(", ", names)}");
        Console.WriteLine($"Expected address: {string.Join(", ", cfg.Dns.Names.Values.Distinct())}  Tiny DNS: {cfg.Dns.Bind}");

        // 1. The proxy itself, asked directly (no name resolution involved).
        Console.WriteLine("\n[1] Proxy answers for each name (connects straight to the listener, sends the name in the Host header)");
        var reverse = cfg.Listeners.Where(l => l.Mode == "http-reverse").ToList();
        foreach (var n in names)
        {
            var l = reverse.FirstOrDefault(x => x.Routes.ContainsKey(n)) ?? reverse.FirstOrDefault();
            if (l == null) { Line("SKIP", n + ": no http-reverse listener in the settings"); continue; }
            var ep = new IPEndPoint(l.Bind.Address.Equals(IPAddress.Any) ? IPAddress.Loopback : l.Bind.Address, l.Bind.Port);
            var (ok, text) = HttpHead(ep, n);
            if (!ok) Line("FAIL", $"{n}: {text} (is the proxy running on {ep}?)");
            else if (!l.Routes.ContainsKey(n)) Line("SKIP", $"{n}: the proxy answers '{text}' - no route for this name yet (add it under Routes)");
            else Line("PASS", $"{n}: {text}");
        }

        // 2. The tiny DNS, asked directly on its own address.
        Console.WriteLine($"\n[2] Tiny DNS on {cfg.Dns.Bind} (asked directly)");
        bool dnsUp = false;
        foreach (var n in names)
        {
            var (rc, ip, err) = Ask(cfg.Dns.Bind, n, 1);
            if (err != null)
            {
                Line(cfg.Mode == "full" ? "FAIL" : "SKIP", $"{n}: {err}" + (cfg.Mode == "full" ? " (is the proxy running with --mode full?)" : " (mode is proxy; start with --mode full to test the DNS)"));
                continue;
            }
            dnsUp = true;
            if (!cfg.Dns.Names.TryGetValue(n, out var want)) { Line("SKIP", $"{n}: not in the settings, DNS says {(ip?.ToString() ?? "rcode " + rc)}"); continue; }
            if (ip != null && ip.Equals(want)) Line("PASS", $"{n} A -> {ip}");
            else Line("FAIL", $"{n} A -> {(ip?.ToString() ?? "rcode " + rc)}, expected {want}");
            var (rc6, ip6, err6) = Ask(cfg.Dns.Bind, n, 28);
            if (err6 == null && rc6 == 0) Line("PASS", $"{n} AAAA -> no answer (NODATA), IPv6 clients do not wait");
            else Line("FAIL", $"{n} AAAA -> rcode {rc6} {err6}");
        }
        if (dnsUp)
        {
            var (rc, ip, err) = Ask(cfg.Dns.Bind, "example.com", 1);
            if (err == null && rc == 0 && ip != null) Line("PASS", $"example.com (not in the list) -> {ip} via the OS resolvers: forwarding works");
            else Line("FAIL", $"example.com (not in the list) -> {err ?? "rcode " + rc}: forwarding to the OS resolvers did not give an address (offline, VPN blocking, or no DNS server found)");
        }

        // 3. What the operating system returns: this is what browsers, openssl, .NET, Java and Go end up using.
        Console.WriteLine("\n[3] OS resolution (the normal way every program asks)");
        foreach (var n in names)
        {
            string got;
            IPAddress[] addrs = [];
            try { addrs = Dns.GetHostAddressesAsync(n).WaitAsync(TimeSpan.FromSeconds(8)).GetAwaiter().GetResult(); got = string.Join(",", addrs.Where(x => x.AddressFamily == AddressFamily.InterNetwork)); }
            catch (Exception ex) { got = "ERR " + (ex.InnerException?.Message ?? ex.Message); }
            cfg.Dns.Names.TryGetValue(n, out var want);
            if (want != null && addrs.Contains(want)) Line("PASS", $"{n} -> {got}" + (HostsLookup.Has(n) ? "   (answered by the hosts file, so this does NOT prove the tiny DNS routing)" : "   (not in the hosts file: answered through DNS)"));
            else if (want == null) Line("SKIP", $"{n} -> {got} (not in the settings)");
            else Line("FAIL", $"{n} -> {got}, expected {want}" + (cfg.Mode == "full" ? ": the OS is not routed to the tiny DNS (start the proxy elevated with --mode full and read its [os-routing] lines), or use --hosts-add" : ": add the name to the hosts file (--hosts-add) or use --mode full"));
        }
        Console.WriteLine("  (.NET uses exactly this OS lookup, so [3] is also the .NET result.)");

        // 4. Other runtimes, only when installed.
        Console.WriteLine("\n[4] Runtimes (each one asks for the first name)");
        if (names.Count > 0 && cfg.Dns.Names.TryGetValue(names[0], out var exp))
        {
            RunNode(names[0], exp);
            RunJava(names[0], exp);
            RunGo(names[0], exp);
        }
        else Line("SKIP", "no names to test");

        Console.WriteLine($"\nRESULT: {pass} PASS, {fail} FAIL, {skip} SKIP");
        return fail == 0 ? 0 : 1;
    }

    // ----- helpers -----
    static (bool Ok, string Text) HttpHead(IPEndPoint ep, string host)
    {
        try
        {
            using var c = new TcpClient(ep.AddressFamily);
            using (var cto = new CancellationTokenSource(3000)) c.ConnectAsync(ep, cto.Token).AsTask().GetAwaiter().GetResult();
            using var to = new CancellationTokenSource(15000);   // a routed name is fetched from the real upstream, which can be slow
            using var ns = c.GetStream();
            ns.Write(Encoding.ASCII.GetBytes($"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"));
            var buf = new byte[256];
            int n = ns.ReadAsync(buf, to.Token).AsTask().GetAwaiter().GetResult();
            var first = Encoding.ASCII.GetString(buf, 0, n).Split('\n')[0].Trim();
            return first.StartsWith("HTTP/") ? (true, first) : (false, "no HTTP answer");
        }
        catch (OperationCanceledException) { return (true, "the proxy accepted the connection but the upstream did not answer within 15 s (upstream slow; the proxy itself is up)"); }
        catch (Exception ex) { return (false, ex.InnerException?.Message ?? ex.Message); }
    }

    static (int Rcode, IPAddress? A, string? Err) Ask(IPEndPoint server, string name, int type)
    {
        try
        {
            using var c = new UdpClient(server.AddressFamily);
            using var to = new CancellationTokenSource(2500);
            ushort id = (ushort)Random.Shared.Next(1, 65535);
            var q = DnsWire.BuildQuery(name, type, id);
            c.SendAsync(q, q.Length, server).GetAwaiter().GetResult();
            var r = c.ReceiveAsync(to.Token).AsTask().GetAwaiter().GetResult().Buffer;
            var (rc, a) = DnsWire.ReadReply(r);
            return (rc, a, null);
        }
        catch (OperationCanceledException) { return (-1, null, "no answer (not listening?)"); }
        catch (Exception ex) { return (-1, null, ex.InnerException?.Message ?? ex.Message); }
    }

    static string Temp()
    {
        var d = Path.Combine(Path.GetTempPath(), "pkiproxy-probe-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(d);
        return d;
    }

    // Only the line that starts with the marker counts: runtimes print other text (for example Java's "Picked up JAVA_TOOL_OPTIONS ...").
    static void Verdict(string runtime, string label, string marker, (int Code, string Out) r, IPAddress exp)
    {
        if (r.Code == -2) { Line("SKIP", runtime + ": not installed"); return; }
        var o = r.Out.Replace("\r", "").Split('\n').FirstOrDefault(l => l.StartsWith(marker)) ?? (r.Code == 0 ? "no result line" : r.Out.Split('\n')[0]);
        var ips = o[marker.Length..].Split([' ', ','], StringSplitOptions.RemoveEmptyEntries);
        if (r.Code == 0 && ips.Contains(exp.ToString())) Line("PASS", $"{runtime} {label}: {o}");
        else Line("FAIL", $"{runtime} {label}: {o}");
    }

    static void RunNode(string name, IPAddress exp)
    {
        // lookup() uses the OS (getaddrinfo); resolve4() has its own DNS client and asks the OS's DNS servers directly.
        const string js = "const d=require('dns');d.lookup(process.argv[1],{all:true,family:4},(e,a)=>{console.log('lookup '+(e?'ERR '+e.code:a.map(x=>x.address).join(',')));" +
                          "d.resolve4(process.argv[1],(e2,b)=>{console.log('resolve4 '+(e2?'ERR '+e2.code:b.join(',')));});});";
        var r = Probe.Run("node", ["-e", js, name], 15000);
        if (r.Code == -2) { Line("SKIP", "node: not installed"); return; }
        var lookup = r.Out.Replace("\r", "").Split('\n').FirstOrDefault(l => l.StartsWith("lookup")) ?? r.Out;
        Verdict("node", "dns.lookup", "lookup", (r.Code, lookup), exp);
        var res = r.Out.Replace("\r", "").Split('\n').FirstOrDefault(l => l.StartsWith("resolve4"));
        if (res != null) Line("INFO", "node dns.resolve4: " + res["resolve4 ".Length..] + "  (bypasses the OS rules; only works when the OS DNS itself is the tiny DNS. Use dns.lookup or fetch/http, which use the OS.)");
    }

    static void RunJava(string name, IPAddress exp)
    {
        var d = Temp();
        try
        {
            File.WriteAllText(Path.Combine(d, "Probe.java"),
                "import java.net.*;\npublic class Probe { public static void main(String[] a) { try { var s = new StringBuilder(); for (var x : InetAddress.getAllByName(a[0])) { if (x instanceof Inet4Address) { if (s.length() > 0) s.append(','); s.append(x.getHostAddress()); } } System.out.println(\"getAllByName \" + s); } catch (Exception e) { System.out.println(\"getAllByName ERR \" + e.getClass().getSimpleName()); } } }\n");
            Verdict("java", "InetAddress", "getAllByName", Probe.Run("java", ["Probe.java", name], 45000, d), exp);
        }
        finally { try { Directory.Delete(d, true); } catch { } }
    }

    static void RunGo(string name, IPAddress exp)
    {
        var d = Temp();
        try
        {
            File.WriteAllText(Path.Combine(d, "probe.go"),
                "package main\nimport (\"fmt\"; \"net\"; \"os\"; \"strings\")\nfunc main() {\n a, err := net.LookupHost(os.Args[1])\n if err != nil { fmt.Println(\"LookupHost ERR \" + err.Error()); return }\n fmt.Println(\"LookupHost \" + strings.Join(a, \",\"))\n}\n");
            Verdict("go", "net.LookupHost", "LookupHost", Probe.Run("go", ["run", "probe.go", name], 90000, d), exp);
        }
        finally { try { Directory.Delete(d, true); } catch { } }
    }
}
