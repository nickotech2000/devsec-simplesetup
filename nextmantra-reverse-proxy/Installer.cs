/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

using System.Diagnostics;
using System.Net;
using System.Text;

// ===== --install-service / --install-systemd (and the matching uninstall switches) =====
static class Installer
{
    const string LinuxDir = "/opt/pkiproxy";
    const string LinuxUnit = "/etc/systemd/system/pkiproxy.service";
    const string LinuxUser = "pkiproxy";

    static string WinDir => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles), "AgantraPkiProxy");
    static string WinData => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "pkiproxy");

    public static (int Code, string Out) Exec(string file, params string[] args)
    {
        var psi = new ProcessStartInfo(file) { RedirectStandardOutput = true, RedirectStandardError = true, UseShellExecute = false, CreateNoWindow = true };
        foreach (var x in args) psi.ArgumentList.Add(x);
        try
        {
            using var p = Process.Start(psi)!;
            var o = p.StandardOutput.ReadToEnd() + p.StandardError.ReadToEnd();
            p.WaitForExit();
            return (p.ExitCode, o.Trim());
        }
        catch (Exception ex) { return (-1, ex.Message); }
    }

    static int Step(string text, (int Code, string Out) r, bool must = true)
    {
        bool ok = r.Code == 0;
        Console.WriteLine((ok ? "  ok   " : must ? "  FAIL " : "  skip ") + text + (ok || r.Out.Length == 0 ? "" : " -> " + r.Out));
        return ok || !must ? 0 : 1;
    }

    public static int Run(Args a)
    {
        Program.Banner();
        if (!Environment.IsPrivilegedProcess) { Console.Error.WriteLine("Run this from an elevated prompt (Administrator / root)."); return 2; }
        try
        {
            if (a.Has("install-service")) { RequireOs(OperatingSystem.IsWindows(), "Windows"); return InstallWindows(a); }
            if (a.Has("uninstall-service")) { RequireOs(OperatingSystem.IsWindows(), "Windows"); return UninstallWindows(a); }
            if (a.Has("install-systemd")) { RequireOs(OperatingSystem.IsLinux(), "Linux"); return InstallLinux(a); }
            RequireOs(OperatingSystem.IsLinux(), "Linux");
            return UninstallLinux(a);
        }
        catch (Exception ex) { Console.Error.WriteLine("ERROR: " + ex.Message); return 3; }
    }

    static void RequireOs(bool ok, string os) { if (!ok) throw new InvalidOperationException("This switch is for " + os + " only."); }

    static string Self => Environment.ProcessPath ?? throw new InvalidOperationException("Cannot find the executable path");

    // Copies the executable and, when missing, the config next to it.
    static string Deploy(Args a, string dir)
    {
        Directory.CreateDirectory(dir);
        var dest = Path.Combine(dir, Path.GetFileName(Self));
        if (!string.Equals(Path.GetFullPath(Self), Path.GetFullPath(dest), StringComparison.OrdinalIgnoreCase)) File.Copy(Self, dest, true);
        var cfgDest = Path.Combine(dir, "appsettings.json");
        var cfgSrc = Paths.Config(a);
        if (!File.Exists(cfgDest) && File.Exists(cfgSrc)) File.Copy(cfgSrc, cfgDest);
        Console.WriteLine("  ok   files in " + dir + (File.Exists(cfgDest) ? "" : " (no appsettings.json found: put one there)"));
        return dest;
    }

    // ----- Windows -----
    static bool ServiceExists() => Exec("sc.exe", "query", WinService.Name).Code == 0;

    static void WaitStopped()
    {
        for (int i = 0; i < 20; i++)
        {
            var q = Exec("sc.exe", "query", WinService.Name);
            if (q.Code != 0 || q.Out.Contains("STOPPED")) return;
            Thread.Sleep(500);
        }
    }

    static int InstallWindows(Args a)
    {
        int bad = 0;
        bool exists = ServiceExists();
        if (exists) { Exec("sc.exe", "stop", WinService.Name); WaitStopped(); }
        var exe = Deploy(a, WinDir);
        Directory.CreateDirectory(WinData);
        bad += Step("cache folder rights", Exec("icacls.exe", WinData, "/grant", "NT AUTHORITY\\LocalService:(OI)(CI)M"), false);
        var bin = "\"" + exe + "\" --service";
        bad += exists
            ? Step("service updated", Exec("sc.exe", "config", WinService.Name, "binPath=", bin, "start=", "auto"))
            : Step("service created (LocalService, automatic start)", Exec("sc.exe", "create", WinService.Name, "binPath=", bin, "start=", "auto",
                "obj=", "NT AUTHORITY\\LocalService", "DisplayName=", "Agantra PKI Proxy"));
        Step("description", Exec("sc.exe", "description", WinService.Name, "CRL/OCSP reverse proxy and TCP/HTTP relay (Agantra Inovatif OU)"), false);
        Step("restart on failure", Exec("sc.exe", "failure", WinService.Name, "reset=", "86400", "actions=", "restart/5000/restart/5000/restart/30000"), false);
        if (a.Has("with-hosts")) bad += Hosts.Apply(true, Path.Combine(WinDir, "appsettings.json"), a);
        bad += Step("service started", Exec("sc.exe", "start", WinService.Name));
        return bad == 0 ? 0 : 3;
    }

    static int UninstallWindows(Args a)
    {
        int bad = 0;
        if (a.Has("with-hosts")) bad += Hosts.Apply(false, Path.Combine(WinDir, "appsettings.json"), a);
        if (ServiceExists())
        {
            Exec("sc.exe", "stop", WinService.Name);
            WaitStopped();
            bad += Step("service deleted", Exec("sc.exe", "delete", WinService.Name));
        }
        else Console.WriteLine("  skip service not installed");
        try
        {
            if (!string.Equals(Path.GetDirectoryName(Path.GetFullPath(Self)), WinDir, StringComparison.OrdinalIgnoreCase) && Directory.Exists(WinDir)) Directory.Delete(WinDir, true);
            if (Directory.Exists(WinData)) Directory.Delete(WinData, true);
        }
        catch { Console.WriteLine("  skip some files could not be removed (still in use?)"); }
        return bad == 0 ? 0 : 3;
    }

    // ----- Linux -----
    static int InstallLinux(Args a)
    {
        int bad = 0;
        if (Exec("id", "-u", LinuxUser).Code != 0)
            bad += Step("system user " + LinuxUser, Exec("useradd", "--system", "--no-create-home", "--shell", "/usr/sbin/nologin", LinuxUser));
        Exec("systemctl", "stop", "pkiproxy");
        var exe = Deploy(a, LinuxDir);
        File.SetUnixFileMode(exe, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute | UnixFileMode.GroupRead | UnixFileMode.GroupExecute | UnixFileMode.OtherRead | UnixFileMode.OtherExecute);
        var cfg = Path.Combine(LinuxDir, "appsettings.json");
        if (File.Exists(cfg)) File.SetUnixFileMode(cfg, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.GroupRead | UnixFileMode.OtherRead);
        Exec("restorecon", "-R", LinuxDir);

        File.WriteAllText(LinuxUnit, $"""
            [Unit]
            Description=Agantra PKI proxy
            After=network-online.target
            Wants=network-online.target

            [Service]
            ExecStart={exe} --service
            User={LinuxUser}
            Restart=always
            RestartSec=3
            AmbientCapabilities=CAP_NET_BIND_SERVICE
            CapabilityBoundingSet=CAP_NET_BIND_SERVICE
            NoNewPrivileges=true
            ProtectSystem=strict
            ProtectHome=true
            PrivateTmp=true
            PrivateDevices=true
            ProtectKernelTunables=true
            ProtectKernelModules=true
            ProtectControlGroups=true
            RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
            StateDirectory=pkiproxy
            RuntimeDirectory=pkiproxy
            MemoryMax=128M

            [Install]
            WantedBy=multi-user.target
            """.Replace("\r\n", "\n") + "\n");
        Console.WriteLine("  ok   unit file " + LinuxUnit);
        bad += Step("daemon-reload", Exec("systemctl", "daemon-reload"));
        if (a.Has("with-hosts")) bad += Hosts.Apply(true, cfg, a);
        bad += Step("enable and start", Exec("systemctl", "enable", "--now", "pkiproxy"));
        return bad == 0 ? 0 : 3;
    }

    static int UninstallLinux(Args a)
    {
        int bad = 0;
        if (a.Has("with-hosts")) bad += Hosts.Apply(false, Path.Combine(LinuxDir, "appsettings.json"), a);
        Step("disable and stop", Exec("systemctl", "disable", "--now", "pkiproxy"), false);
        try { if (File.Exists(LinuxUnit)) File.Delete(LinuxUnit); } catch (Exception ex) { Console.WriteLine("  FAIL unit: " + ex.Message); bad++; }
        Step("daemon-reload", Exec("systemctl", "daemon-reload"), false);
        try { if (Directory.Exists(LinuxDir)) Directory.Delete(LinuxDir, true); } catch { Console.WriteLine("  skip " + LinuxDir + " not removed"); }
        Console.WriteLine("  note the system user '" + LinuxUser + "' and /var/lib/pkiproxy are kept");
        return bad == 0 ? 0 : 3;
    }
}

// ===== --hosts-add / --hosts-remove / --hosts-status: names come from the Routes of the same appsettings.json =====
static class Hosts
{
    const string Begin = "# BEGIN pkiproxy (managed, do not edit)";
    const string End = "# END pkiproxy";
    const string OffTag = "#pkiproxy-off# ";
    const string SplitTag = "#pkiproxy-split#";

    // --hosts-file <path> points the switches at another file (testing, or a hosts file in a container image).
    static string HostsPath(Args a) => a.Value("hosts-file") ?? (OperatingSystem.IsWindows()
        ? Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts")
        : "/etc/hosts");

    // Exit codes: 0 ok, 1 status found changes needed, 2 not elevated, 3 error
    public static int Run(Args a)
    {
        Program.Banner();
        bool status = a.Has("hosts-status"), dry = a.Has("dry-run");
        if (!status && !dry && a.Value("hosts-file") == null && !Environment.IsPrivilegedProcess) { Console.Error.WriteLine("Run this from an elevated prompt (Administrator / root)."); return 2; }
        try
        {
            if (status) return Status(Paths.Config(a), a) ? 0 : 1;
            return Apply(a.Has("hosts-add"), Paths.Config(a), a) == 0 ? 0 : 3;
        }
        catch (Exception ex) { Console.Error.WriteLine("ERROR: " + ex.Message); return 3; }
    }

    static (string[] Names, IPAddress Ip, bool V6) Setup(string cfgPath, Args a)
    {
        var names = Config.Load(cfgPath).HostNames();
        if (names.Length == 0) throw new InvalidOperationException("No http-reverse route names in " + cfgPath);
        if (!IPAddress.TryParse(a.Value("ip") ?? "127.0.0.1", out var ip)) throw new InvalidOperationException("--ip is not a valid address");
        return (names, ip, a.Has("ipv6"));
    }

    static List<string> ReadLines(string text, out string eol)
    {
        eol = text.Contains("\r\n") ? "\r\n" : "\n";
        var lines = text.Replace("\r\n", "\n").Split('\n').ToList();
        if (lines.Count > 0 && lines[^1].Length == 0) lines.RemoveAt(lines.Count - 1);
        return lines;
    }

    // Removes our block and puts back every line we switched off.
    static List<string> Restore(List<string> lines)
    {
        var res = new List<string>();
        bool inBlock = false;
        foreach (var line in lines)
        {
            if (inBlock) { if (line.TrimEnd() == End) inBlock = false; continue; }
            if (line.TrimEnd() == Begin) { inBlock = true; continue; }
            if (line.EndsWith(SplitTag, StringComparison.Ordinal)) continue;
            res.Add(line.StartsWith(OffTag, StringComparison.Ordinal) ? line[OffTag.Length..] : line);
        }
        return res;
    }

    static string[] Tokens(string line)
    {
        int h = line.IndexOf('#');
        return (h >= 0 ? line[..h] : line).Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
    }

    static bool Same(string token, IPAddress ip) => IPAddress.TryParse(token, out var t) && t.Equals(ip);

    static bool Status(string cfgPath, Args a)
    {
        var (names, ip, v6) = Setup(cfgPath, a);
        var lines = ReadLines(File.ReadAllText(HostsPath(a)), out _);
        bool allOk = true;
        foreach (var n in names)
        {
            string? first = lines.Select(Tokens).Where(t => t.Length >= 2 && t.Skip(1).Any(x => x.Equals(n, StringComparison.OrdinalIgnoreCase))).Select(t => t[0]).FirstOrDefault();
            bool ok = first != null && Same(first, ip);
            allOk &= ok;
            Console.WriteLine($"  {(ok ? "ok      " : first == null ? "MISSING " : "CONFLICT")} {n}" + (first == null ? "" : " -> " + first));
        }
        return allOk;
    }

    // add=true writes the managed block, add=false removes it. Returns 0 on success.
    public static int Apply(bool add, string cfgPath, Args a)
    {
        var (names, ip, v6) = Setup(cfgPath, a);
        bool dry = a.Has("dry-run");
        var path = HostsPath(a);
        var oldText = File.ReadAllText(path);
        var lines = Restore(ReadLines(oldText, out string eol));
        var notes = new List<string>();

        if (add)
        {
            var mine = names.ToHashSet(StringComparer.OrdinalIgnoreCase);
            var ours = new List<IPAddress> { ip };
            if (v6) ours.Add(IPAddress.IPv6Loopback);
            var outLines = new List<string>();
            foreach (var line in lines)
            {
                var t = Tokens(line);
                bool conflict = t.Length >= 2 && t.Skip(1).Any(mine.Contains) && !ours.Any(o => Same(t[0], o));
                if (!conflict) { outLines.Add(line); continue; }
                notes.Add("  switch off: " + line.Trim());
                outLines.Add(OffTag + line);
                var others = t.Skip(1).Where(x => !mine.Contains(x)).ToArray();
                if (others.Length > 0) outLines.Add(t[0] + " " + string.Join(' ', others) + " " + SplitTag);
            }
            outLines.Add(Begin);
            foreach (var o in ours)
                foreach (var chunk in names.Chunk(8)) outLines.Add(o + " " + string.Join(' ', chunk));
            outLines.Add(End);
            lines = outLines;
            notes.Add("  block: " + ip + " " + string.Join(' ', names));
        }

        var newText = string.Join(eol, lines) + eol;
        if (newText == oldText) { Console.WriteLine("  ok   hosts file already up to date"); return 0; }
        foreach (var n in notes) Console.WriteLine(n);
        if (dry) { Console.WriteLine("  dry-run: the hosts file would be changed (nothing written)"); return 0; }

        var bak = path + ".pkiproxy.bak";
        if (!File.Exists(bak)) File.Copy(path, bak);
        Write(path, newText);
        if (a.Value("hosts-file") == null) FlushDns();
        Console.WriteLine("  ok   hosts file " + (add ? "updated" : "restored") + " (backup: " + bak + ")");
        return 0;
    }

    // The resolver caches hosts entries on Windows and macOS; Linux reads /etc/hosts on every lookup.
    static void FlushDns()
    {
        if (OperatingSystem.IsWindows()) Installer.Exec("ipconfig.exe", "/flushdns");
        else if (OperatingSystem.IsMacOS()) { Installer.Exec("dscacheutil", "-flushcache"); Installer.Exec("killall", "-HUP", "mDNSResponder"); }
    }

    static void Write(string path, string text)
    {
        var enc = new UTF8Encoding(false);
        for (int attempt = 1; ; attempt++)
        {
            try
            {
                if (OperatingSystem.IsWindows())
                {
                    var tmp = path + ".pkiproxy.tmp";
                    File.WriteAllText(tmp, text, enc);
                    File.Replace(tmp, path, null);   // keeps the ACL of the hosts file
                }
                else File.WriteAllText(path, text, enc);   // in place: keeps the SELinux label and mode
                return;
            }
            catch (IOException) when (attempt < 5) { Thread.Sleep(300); }
        }
    }
}
