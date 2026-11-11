/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32;

// ===== --env-report: read-only. Looks at the machine and writes a text report; changes nothing. =====
// The report holds the machine name, adapter names and DNS server addresses. Read it before you send it to anybody.
static class EnvReport
{
    static readonly StringBuilder sb = new();

    static void Out(string s = "") { sb.AppendLine(s); Console.WriteLine(s); }
    static void Head(string s) { Out(); Out("== " + s); }
    static void Kv(string k, string v) => Out("  " + k.PadRight(26) + v);

    static string Cmd(string file, params string[] args)
    {
        var r = Probe.Run(file, args, 6000);
        return r.Code == -2 ? "(not installed)" : r.Out.Replace("\r", "").Split('\n').FirstOrDefault(l => l.Trim().Length > 0 && !l.StartsWith("Picked up"))?.Trim() ?? "";
    }

    public static int Run(Args a)
    {
        Program.Banner();
        Out("Agantra PKI proxy environment report, " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss zzz"));
        Out("Read-only: nothing on this machine is changed.");

        Config? cfg = null;
        string cfgErr = "";
        try { cfg = Config.Load(Paths.Config(a)); } catch (Exception ex) { cfgErr = ex.Message; }

        Head("Program");
        Kv("executable", Environment.ProcessPath ?? "?");
        Kv("settings file", Paths.Config(a) + (File.Exists(Paths.Config(a)) ? "" : "  (MISSING)"));
        Kv("settings valid", cfg != null ? "yes, mode '" + cfg.Mode + "'" : "NO: " + cfgErr);
        Kv("elevated (admin/root)", Environment.IsPrivilegedProcess ? "yes" : "no");
        Kv(".NET runtime", RuntimeInformation.FrameworkDescription);

        Head("Operating system");
        Kv("description", RuntimeInformation.OSDescription);
        Kv("architecture", RuntimeInformation.OSArchitecture.ToString());
        Kv("machine name", Environment.MachineName);
        if (OperatingSystem.IsWindows()) WindowsFacts(cfg);
        else LinuxFacts(cfg);

        Head("Network adapters (up)");
        try
        {
            foreach (var nic in NetworkInterface.GetAllNetworkInterfaces())
            {
                if (nic.OperationalStatus != OperationalStatus.Up || nic.NetworkInterfaceType == NetworkInterfaceType.Loopback) continue;
                var dns = nic.GetIPProperties().DnsAddresses.Select(d => d.ToString()).ToArray();
                string text = (nic.Name + " " + nic.Description).ToLowerInvariant();
                string vpn = new[] { "astrill", "mullvad", "wireguard", "wintun", "openvpn", "tap-windows", "nordlynx", "tun", "vpn" }.Any(text.Contains) ? "  <- looks like a VPN" : "";
                Out($"  {nic.Name} [{nic.NetworkInterfaceType}] {nic.Description}{vpn}");
                Out("      DNS servers: " + (dns.Length == 0 ? "(none)" : string.Join(", ", dns)));
            }
        }
        catch (Exception ex) { Out("  cannot read: " + ex.Message); }

        Head("Ports the tiny DNS and the proxy need (a test bind, closed at once)");
        var dnsEp = cfg?.Dns.Bind ?? new IPEndPoint(IPAddress.Parse("127.0.0.2"), 53);
        Kv("UDP " + dnsEp, BindTest(dnsEp, true));
        Kv("TCP " + dnsEp, BindTest(dnsEp, false));
        foreach (var l in cfg?.Listeners ?? [])
        {
            if (l.Bind.Port == 0) continue;
            Kv("TCP " + l.Bind + " [" + l.Name + "]", BindTest(new IPEndPoint(l.Bind.Address, l.Bind.Port), false));
        }

        Head("Names from the settings in the hosts file");
        string hosts = OperatingSystem.IsWindows() ? Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts") : "/etc/hosts";
        try
        {
            var lines = File.ReadAllLines(hosts).Select(l => l.Trim()).Where(l => l.Length > 0 && !l.StartsWith('#')).ToArray();
            Kv("hosts file", hosts + " (" + lines.Length + " active lines)");
            foreach (var n in cfg?.Dns.Names.Keys.OrderBy(x => x, StringComparer.Ordinal) ?? Enumerable.Empty<string>())
            {
                var hit = lines.FirstOrDefault(l => l.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries).Skip(1).Any(h => h.Equals(n, StringComparison.OrdinalIgnoreCase)));
                Kv(n, hit ?? "(not in the hosts file)");
            }
        }
        catch (Exception ex) { Out("  cannot read " + hosts + ": " + ex.Message); }

        Head("Runtimes");
        Kv("dotnet", Cmd("dotnet", "--version"));
        Kv("node", Cmd("node", "--version"));
        Kv("java", Cmd("java", "-version"));
        Kv("go", Cmd("go", "version"));

        Out();
        Out("End of report.");
        try
        {
            var file = Path.Combine(Directory.GetCurrentDirectory(), $"env-report-{Environment.MachineName}-{DateTime.Now:yyyyMMdd-HHmmss}.txt");
            File.WriteAllText(file, sb.ToString());
            Console.WriteLine("Saved: " + file);
        }
        catch (Exception ex) { Console.WriteLine("(could not save the report file: " + ex.Message + ")"); }
        return 0;
    }

    static string BindTest(IPEndPoint ep, bool udp)
    {
        try
        {
            if (udp) { using var u = new UdpClient(ep); }
            else { var t = new TcpListener(ep); t.Start(); t.Stop(); }
            return "free";
        }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressAlreadyInUse) { return "IN USE by another program"; }
        catch (SocketException ex) when (ex.SocketErrorCode is SocketError.AccessDenied) { return "denied (needs Administrator/root or the port is reserved)"; }
        catch (SocketException ex) when (ex.SocketErrorCode == SocketError.AddressNotAvailable) { return "address not available on this machine"; }
        catch (Exception ex) { return "cannot test: " + ex.Message; }
    }

    // ----- Windows: registry and files only, no helper processes -----
    static void WindowsFacts(Config? cfg)
    {
        if (!OperatingSystem.IsWindows()) return;
        try
        {
            using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows NT\CurrentVersion");
            Kv("Windows", $"{k?.GetValue("ProductName")} {k?.GetValue("DisplayVersion")} build {k?.GetValue("CurrentBuild")}.{k?.GetValue("UBR")}");
            using var tcp = Registry.LocalMachine.OpenSubKey(@"SYSTEM\CurrentControlSet\Services\Tcpip\Parameters");
            var dom = tcp?.GetValue("Domain") as string;
            Kv("DNS domain (joined?)", string.IsNullOrEmpty(dom) ? "(none: not domain-joined)" : dom + "  <- domain-joined: group policy may own the name-resolution rules");
        }
        catch (Exception ex) { Kv("registry", "cannot read: " + ex.Message); }

        Head("Windows name-resolution rules (NRPT) already present");
        foreach (var (path, label, root) in new[]
        {
            (@"SYSTEM\CurrentControlSet\Services\Dnscache\Parameters\DnsPolicyConfig", "local rules", Registry.LocalMachine),
            (@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig", "group-policy rules", Registry.LocalMachine),
        })
        {
            try
            {
                using var k = root.OpenSubKey(path);
                var subs = k?.GetSubKeyNames() ?? [];
                Kv(label, subs.Length + " rule(s)");
                foreach (var s in subs)
                {
                    using var r = k!.OpenSubKey(s);
                    var ns = r?.GetValue("Name") is string[] arr ? string.Join(",", arr) : r?.GetValue("Name")?.ToString();
                    var srv = r?.GetValue("GenericDNSServers")?.ToString();
                    Out($"      {ns}  -> {srv}");
                }
            }
            catch (Exception ex) { Kv(label, "cannot read: " + ex.Message); }
        }

        Head("WSL on this Windows machine");
        Kv("wsl.exe present", File.Exists(Path.Combine(Environment.SystemDirectory, "wsl.exe")) ? "yes" : "no");
        var cfgFile = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.UserProfile), ".wslconfig");
        if (File.Exists(cfgFile)) { Kv(".wslconfig", "present:"); foreach (var l in File.ReadAllLines(cfgFile).Where(x => x.Trim().Length > 0)) Out("      " + l.Trim()); }
        else Kv(".wslconfig", "(none: default NAT networking)");
    }

    // ----- Linux (including WSL) -----
    static void LinuxFacts(Config? cfg)
    {
        string os = "?";
        try { os = File.ReadLines("/etc/os-release").FirstOrDefault(l => l.StartsWith("PRETTY_NAME="))?.Split('=')[1].Trim('"') ?? "?"; } catch { }
        Kv("distribution", os);
        string kernel = "?";
        try { kernel = File.ReadAllText("/proc/version").Trim(); } catch { }
        Kv("kernel", kernel.Length > 110 ? kernel[..110] + "..." : kernel);
        bool wsl = kernel.Contains("microsoft", StringComparison.OrdinalIgnoreCase) || Environment.GetEnvironmentVariable("WSL_DISTRO_NAME") != null;
        Kv("WSL", wsl ? "yes (" + Environment.GetEnvironmentVariable("WSL_DISTRO_NAME") + ")" : "no");
        string init = "?";
        try { init = File.ReadAllText("/proc/1/comm").Trim(); } catch { }
        Kv("PID 1", init + (init == "systemd" ? "" : "  <- systemd is not running; systemd-resolved cannot be used"));

        Head("DNS setup");
        Kv("systemd-resolved", Cmd("systemctl", "is-active", "systemd-resolved"));
        Kv("NetworkManager", Cmd("systemctl", "is-active", "NetworkManager"));
        Kv("resolvectl present", File.Exists("/usr/bin/resolvectl") || File.Exists("/bin/resolvectl") ? "yes" : "no");
        try
        {
            var fi = new FileInfo("/etc/resolv.conf");
            Kv("/etc/resolv.conf", fi.LinkTarget != null ? "symlink -> " + fi.LinkTarget : "regular file");
            foreach (var l in File.ReadLines("/etc/resolv.conf").Where(l => l.StartsWith("nameserver") || l.StartsWith("search") || l.StartsWith("# This file is generated") || l.Contains("generated by")).Take(8)) Out("      " + l.Trim());
        }
        catch (Exception ex) { Kv("/etc/resolv.conf", "cannot read: " + ex.Message); }
        try { Kv("nsswitch hosts", File.ReadLines("/etc/nsswitch.conf").FirstOrDefault(l => l.TrimStart().StartsWith("hosts:"))?.Trim() ?? "?"); } catch { }
        try
        {
            var dir = "/etc/systemd/resolved.conf.d";
            Kv("resolved.conf.d", Directory.Exists(dir) ? string.Join(", ", Directory.GetFiles(dir).Select(Path.GetFileName)) is { Length: > 0 } s ? s : "(empty)" : "(none)");
        }
        catch { }

        if (wsl)
        {
            Head("WSL settings");
            Kv("networking mode", Cmd("wslinfo", "--networking-mode"));
            try { if (File.Exists("/etc/wsl.conf")) { Kv("/etc/wsl.conf", "present:"); foreach (var l in File.ReadAllLines("/etc/wsl.conf").Where(x => x.Trim().Length > 0)) Out("      " + l.Trim()); } else Kv("/etc/wsl.conf", "(none)"); } catch { }
        }

        Head("Security");
        Kv("SELinux", Cmd("getenforce"));
        Kv("firewalld", Cmd("systemctl", "is-active", "firewalld"));
    }
}
