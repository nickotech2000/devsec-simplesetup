/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Win32;

// ===== --mode full: point the OS at the tiny DNS for exactly the listed names, and take it away again =====
// Windows : one name-resolution (NRPT) rule per name, tagged AgantraPkiProxy, no wildcard. Nothing else is touched.
// Linux   : systemd-resolved, on one helper link pkiproxy0 (a dummy network interface, address 192.0.2.53) with routing domains
//           ~name. It lives in memory, not in a file, so a reboot or --clean removes it. Without systemd-resolved (or without
//           the ip command / dummy module) nothing is changed and the fallback is printed.
// Every change is written to proxy-changes.json. --clean (or a normal stop, or the next start after a crash) removes it.
static class OsRouting
{
    public const string Tag = "AgantraPkiProxy";
    const string LinkName = "pkiproxy0";                           // Linux helper link (a dummy network interface)
    static readonly IPAddress LinkAddr = IPAddress.Parse("192.0.2.53");   // TEST-NET-1: reserved for documentation, never routed
    static bool applied;

    static string DataDir => OperatingSystem.IsWindows()
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData), "pkiproxy")
        : "/var/lib/pkiproxy";
    static string StateFile => Path.Combine(DataDir, "proxy-changes.json");

    static void Say(string s) => Console.WriteLine("  [os-routing] " + s);

    // ----- called by the server -----
    // Start / reload in full mode. Never throws: the tiny DNS keeps working even when the OS cannot be routed.
    public static void Sync(Config cfg, bool allow)
    {
        try
        {
            RemoveInternal(quiet: true);   // leftovers of a crash, or the previous list on reload
            if (cfg.Mode != "full" || !allow) return;
            if (!Environment.IsPrivilegedProcess) { Say("not elevated: the OS was NOT pointed at the tiny DNS. Run as Administrator/root, or use --hosts-add."); return; }
            if (cfg.Dns.Bind.Port != 53 && OperatingSystem.IsWindows()) { Say("Windows name-resolution rules can only use port 53, but Dns:Bind is " + cfg.Dns.Bind + ". Not applied."); return; }
            var names = cfg.Dns.Names.Keys.OrderBy(n => n, StringComparer.Ordinal).ToArray();
            if (names.Length == 0) return;

            bool ok = OperatingSystem.IsWindows() ? ApplyWindows(cfg, names) : ApplyLinux(cfg, names);
            if (!ok) return;
            applied = true;
            WriteState(cfg, names);

            // Check that the OS really uses it; if not, undo at once so nothing half-working is left behind.
            // A name that is also in the hosts file would pass without the tiny DNS, so pick one that is not (if there is one).
            var first = names.FirstOrDefault(n => !HostsLookup.Has(n)) ?? names[0];
            var want = cfg.Dns.Names[first];
            bool resolves = false;
            for (int i = 0; i < 3 && !resolves; i++)
            {
                resolves = OperatingSystem.IsLinux() ? CheckLinux(first, want) : CheckOs(first, want);
                if (!resolves) Thread.Sleep(500);
            }
            if (resolves) Say("ok: the OS now resolves " + names.Length + " name(s) through the tiny DNS (" + first + " -> " + want + "; checked with a name " + (HostsLookup.Has(first) ? "that is ALSO in the hosts file, so this check proves little" : "that is not in the hosts file") + "). Removed again on stop or with --clean.");
            else
            {
                RemoveInternal(quiet: true);
                Say("FAILED the check: the OS did not use the tiny DNS for " + first + ". Everything was removed again.");
                Say("Possible reasons: group policy owns the name-resolution rules, a VPN or security product forces its own DNS, or this is not the machine's resolver path.");
                Say("Fallback: --hosts-add (or add the names to the hosts file by hand).");
            }
        }
        catch (Exception ex) { Say("could not apply: " + ex.Message); }
    }

    static bool CheckOs(string name, IPAddress want)
    {
        try { return Dns.GetHostAddressesAsync(name).WaitAsync(TimeSpan.FromSeconds(4)).GetAwaiter().GetResult().Contains(want); } catch { return false; }
    }

    // resolvectl without the hosts file ("synthesize") and without its cache: only a real answer from the tiny DNS counts.
    static bool CheckLinux(string name, IPAddress want)
    {
        var r = Probe.Run("resolvectl", ["query", "--synthesize=no", "--cache=no", "--legend=no", "-4", name], 8000);
        return r.Code == 0 && r.Out.Contains(want.ToString());
    }

    // Normal stop.
    public static void Stop()
    {
        if (!applied) return;
        try { RemoveInternal(quiet: false); } catch (Exception ex) { Say("could not remove: " + ex.Message + " (run --clean)"); }
    }

    // ----- switches: --dns-os-status, --clean [--dry-run] -----
    public static int Run(Args a)
    {
        Program.Banner();
        if (a.Has("dns-os-status")) { Status(); return 0; }
        if (!Environment.IsPrivilegedProcess) { Console.Error.WriteLine("Run this from an elevated prompt (Administrator / root)."); return 2; }
        if (a.Has("dry-run")) { Console.WriteLine("Dry run: would remove the following, nothing is changed."); Status(); return 0; }
        RemoveInternal(quiet: false);
        Status();
        return 0;
    }

    static void Status()
    {
        Console.WriteLine("Recorded changes (" + StateFile + "):");
        Console.WriteLine(File.Exists(StateFile) ? File.ReadAllText(StateFile) : "  (none)");
        if (OperatingSystem.IsWindows())
        {
            var r = Probe.Run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
                $"Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{Tag}' }} | ForEach-Object {{ ($_.Namespace -join ',') + '  -> ' + ($_.NameServers -join ',') }}"], 20000);
            Console.WriteLine("Name-resolution rules tagged " + Tag + ":");
            Console.WriteLine(r.Out.Length == 0 ? "  (none)" : "  " + r.Out.Replace("\n", "\n  "));
            WarnGroupPolicy();
        }
        else
        {
            var r = Probe.Run("resolvectl", ["status", LinkName], 10000);
            Console.WriteLine("systemd-resolved, helper link " + LinkName + ":");
            Console.WriteLine(r.Code == -2 ? "  resolvectl not installed" : "  " + r.Out.Replace("\n", "\n  "));
        }
    }

    // ----- removal (state file first, then anything carrying our tag) -----
    static void RemoveInternal(bool quiet)
    {
        bool any = false;
        if (OperatingSystem.IsWindows())
        {
            if (!Environment.IsPrivilegedProcess) { if (File.Exists(StateFile) && !quiet) Say("not elevated: cannot remove."); return; }
            var r = Probe.Run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command",
                $"$r = @(Get-DnsClientNrptRule | Where-Object {{ $_.Comment -eq '{Tag}' }}); if ($r.Count -gt 0) {{ $r | Remove-DnsClientNrptRule -Force; Clear-DnsClientCache; $r.Count }} else {{ 0 }}"], 30000);
            any = r.Code == 0 && r.Out.Trim() != "0";
            if (r.Code != 0 && r.Code != -2 && !quiet) Say("removal reported: " + r.Out);
        }
        else
        {
            if (!Environment.IsPrivilegedProcess) { return; }
            if (LinuxLinkExists())
            {
                Probe.Run("resolvectl", ["revert", LinkName], 10000);
                Probe.Run("ip", ["link", "del", LinkName], 10000);
                Probe.Run("resolvectl", ["flush-caches"], 10000);
                any = true;
            }
        }
        try { if (File.Exists(StateFile)) File.Delete(StateFile); } catch { }
        applied = false;
        if (any && !quiet) Say("removed the OS routing for the tiny DNS.");
    }

    // ----- Windows -----
    static bool ApplyWindows(Config cfg, string[] names)
    {
        if (HasGroupPolicyRules())
            Say("WARNING: group policy defines name-resolution rules here. When they exist Windows ignores local rules, so this will probably fail the check below.");
        string list = string.Join(",", names.Select(n => "'" + n + "'"));
        // Fixed text only: the names were validated as plain host names, the address is a loopback IPv4/IPv6 literal.
        string script = $"foreach ($n in @({list})) {{ Add-DnsClientNrptRule -Namespace $n -NameServers '{cfg.Dns.Bind.Address}' -Comment '{Tag}' }}; Clear-DnsClientCache";
        var r = Probe.Run("powershell.exe", ["-NoProfile", "-NonInteractive", "-Command", script], 40000);
        if (r.Code != 0) { Say("could not add the rules: " + (r.Out.Length > 300 ? r.Out[..300] : r.Out)); RemoveInternal(true); return false; }
        return true;
    }

    static bool HasGroupPolicyRules()
    {
        if (!OperatingSystem.IsWindows()) return false;
        try { using var k = Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Policies\Microsoft\Windows NT\DNSClient\DnsPolicyConfig"); return (k?.SubKeyCount ?? 0) > 0; }
        catch { return false; }
    }

    static void WarnGroupPolicy() { if (HasGroupPolicyRules()) Console.WriteLine("NOTE: group policy name-resolution rules exist on this machine; local rules are ignored while they do."); }

    // ----- Linux -----
    // systemd-resolved refuses DNS settings on "lo" and ignores a link without an address. So: one helper link (a dummy network
    // interface, pkiproxy0) with one reserved address, the tiny DNS also answers on that address, and resolved is told that
    // the listed names (routing domains ~name, never the default route) go there. Remove = revert + delete the link.
    static bool LinuxLinkExists() => Probe.Run("ip", ["link", "show", LinkName], 8000).Code == 0;

    static bool ApplyLinux(Config cfg, string[] names)
    {
        bool hasTool = File.Exists("/usr/bin/resolvectl") || File.Exists("/bin/resolvectl");
        var active = hasTool ? Probe.Run("systemctl", ["is-active", "systemd-resolved"], 8000).Out.Trim() : "";
        if (!hasTool || active != "active")
        {
            Say("systemd-resolved is not running here, so the OS was NOT pointed at the tiny DNS (nothing was changed).");
            Say("Fallback: " + Path.GetFileName(Environment.ProcessPath ?? "pkiproxy") + " --hosts-add   (or run --env-report and send it to me; the next step covers this system)");
            return false;
        }
        if (Probe.Run("ip", ["-V"], 5000).Code != 0) { Say("the 'ip' command (package iproute2) was not found: nothing was changed. Use --hosts-add."); return false; }

        var r = Probe.Run("ip", ["link", "add", LinkName, "type", "dummy"], 10000);
        if (r.Code != 0) { Say("could not create the helper link " + LinkName + ": " + r.Out + " (a kernel without the dummy module cannot do this). Nothing was changed. Use --hosts-add."); return false; }
        bool ok = Probe.Run("ip", ["addr", "add", LinkAddr + "/32", "dev", LinkName], 10000).Code == 0
               && Probe.Run("ip", ["link", "set", LinkName, "up"], 10000).Code == 0;
        if (ok)
        {
            try { DnsServer.AddListener(new IPEndPoint(LinkAddr, cfg.Dns.Bind.Port)); }
            catch (Exception ex) { Say("the tiny DNS cannot listen on " + LinkAddr + ":" + cfg.Dns.Bind.Port + ": " + ex.Message); ok = false; }
        }
        if (ok)
        {
            string server = cfg.Dns.Bind.Port == 53 ? LinkAddr.ToString() : LinkAddr + ":" + cfg.Dns.Bind.Port;
            var d = Probe.Run("resolvectl", ["dns", LinkName, server], 10000);
            if (d.Code != 0) { Say("resolvectl dns failed: " + d.Out); ok = false; }
        }
        if (ok)
        {
            var dom = new List<string> { "domain", LinkName };
            dom.AddRange(names.Select(n => "~" + n));
            var d = Probe.Run("resolvectl", dom.ToArray(), 10000);
            if (d.Code != 0) { Say("resolvectl domain failed: " + d.Out); ok = false; }
        }
        if (!ok)
        {
            Probe.Run("resolvectl", ["revert", LinkName], 10000);
            Probe.Run("ip", ["link", "del", LinkName], 10000);
            return false;
        }
        Probe.Run("resolvectl", ["default-route", LinkName, "no"], 10000);   // only the listed names, never the default route
        Probe.Run("resolvectl", ["flush-caches"], 10000);
        return true;
    }

    // ----- record of what was changed -----
    static void WriteState(Config cfg, string[] names)
    {
        try
        {
            Directory.CreateDirectory(DataDir);
            var sb = new StringBuilder();
            sb.Append("{\n  \"tag\": \"").Append(Tag).Append("\",\n  \"time\": \"").Append(DateTime.UtcNow.ToString("o")).Append("\",\n");
            sb.Append("  \"kind\": \"").Append(OperatingSystem.IsWindows() ? "windows-nrpt-rules" : "systemd-resolved-link-pkiproxy0").Append("\",\n");
            sb.Append("  \"dns\": \"").Append(cfg.Dns.Bind).Append("\",\n  \"names\": [");
            sb.Append(string.Join(", ", names.Select(n => "\"" + n + "\""))).Append("]\n}\n");
            File.WriteAllText(StateFile, sb.ToString());
        }
        catch { /* the tag on the rules themselves is enough for --clean */ }
    }
}

// Is the name in the hosts file? (A name that is, resolves without any DNS, which can hide a broken setup.)
static class HostsLookup
{
    public static bool Has(string name)
    {
        try
        {
            string hosts = OperatingSystem.IsWindows() ? Path.Combine(Environment.SystemDirectory, "drivers", "etc", "hosts") : "/etc/hosts";
            foreach (var raw in File.ReadLines(hosts))
            {
                var line = raw.Split('#')[0].Trim();
                if (line.Length == 0) continue;
                var p = line.Split([' ', '\t'], StringSplitOptions.RemoveEmptyEntries);
                if (p.Skip(1).Any(h => h.Equals(name, StringComparison.OrdinalIgnoreCase))) return true;
            }
        }
        catch { }
        return false;
    }
}
