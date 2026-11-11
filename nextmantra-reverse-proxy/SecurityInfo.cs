/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

// audit:allow-file(defender-off) This file only WRITES a text script for the customer's administrator to read and run (--admin-script). The program never runs it and never changes any security product itself.

using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;

// ===== --security-info [--out file]  and  --admin-script [--out-dir dir] =====
// A plain-language hand-over for the administrator of a machine that runs endpoint security software
// (Microsoft Defender, Bitdefender, ESET, other EDR). Read-only: it reports; it changes nothing.
static class SecurityInfo
{
    static readonly StringBuilder T = new();
    static void L(string s = "") => T.AppendLine(s);

    public static int Run(Args a)
    {
        Program.Banner();
        string exe = Environment.ProcessPath ?? "";
        string sha = "?";
        long size = 0;
        try { using var fs = File.OpenRead(exe); size = fs.Length; sha = Convert.ToHexString(SHA256.HashData(fs)).ToLowerInvariant(); } catch { }

        Config? cfg = null;
        string cfgErr = "";
        try { cfg = Config.Load(Paths.Config(a)); } catch (Exception ex) { cfgErr = ex.Message; }

        L("AGANTRA PKI PROXY - SECURITY HAND-OVER FOR THE ADMINISTRATOR");
        L("Author: Nicko Satria Utama   Company: Agantra Inovatif OU   Email: nicko@nextmantra.com");
        L("Created: " + DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss zzz") + " on " + Environment.MachineName);
        L();
        L("1. THE FILE");
        L("   Path     : " + exe);
        L("   Size     : " + size + " bytes");
        L("   SHA-256  : " + sha);
        L("   Signature: " + Signer(exe));
        L("   Compare the SHA-256 with SHA256SUMS-proxy.txt that came with the release (Windows: Get-FileHash <file>, Linux: sha256sum <file>).");
        L("   Do not allow a file whose hash does not match.");
        L("   The program is one self-contained file (.NET single file). On Windows and Linux it may unpack its own libraries to a temporary folder when it starts.");
        L();
        L("2. WHAT IT IS FOR");
        L("   A small local web proxy for certificate revocation traffic (CRL and OCSP) and, optionally, a tiny local DNS server.");
        L("   It lets developer machines reach the internal names crl/ocsp/crt/timestamp/tsa.<domain>.internal without editing the hosts file.");
        L();
        L("3. WHAT IT DOES NOT DO");
        L("   - It does not download, update or run code from the network, and it has no telemetry or logging to the outside.");
        L("   - It does not decode hidden commands, hide its activity, or start anything at boot on its own (a service exists only if the administrator installs one).");
        L("   - It does not change, disable or add exclusions to antivirus or firewall software.");
        L("   - It does not read credentials, browsers, documents or other programs' files.");
        L();
        L("4. NETWORK USE");
        if (cfg == null) L("   (settings file not valid: " + cfgErr + ")");
        else
        {
            foreach (var l in cfg.Listeners)
            {
                L($"   Listens (TCP): {l.Bind}  [{l.Name}, {l.Mode}]  clients allowed: {(l.Allow.Length == 0 ? "none" : "loopback unless listed in Allow")}");
                if (l.Mode == "http-reverse") foreach (var r in l.Routes.OrderBy(x => x.Key, StringComparer.Ordinal)) L($"      {r.Key}  ->  https://{r.Value.Host}:{r.Value.Port}  (outbound)");
                if (l.Mode == "tcp") L($"      relays to {l.TargetHost}:{l.TargetPort} (outbound)");
                if (l.Mode == "http-forward") L("      forward proxy: connects only to hosts matching AllowHosts = " + string.Join(", ", l.AllowHosts) + " on ports " + string.Join(", ", l.AllowPorts) + " (outbound)");
            }
            L("   Mode: " + cfg.Mode + (cfg.Mode == "full" ? $"  - tiny DNS on {cfg.Dns.Bind} (UDP and TCP, loopback only, never an open resolver)" : "  - no DNS server"));
            if (cfg.Mode == "full") L("   Names the tiny DNS answers: " + string.Join(", ", cfg.Dns.Names.Keys.OrderBy(x => x, StringComparer.Ordinal)) + "; every other name is forwarded to the DNS servers the OS already uses.");
        }
        L("   Outbound traffic goes only to the hosts listed above and to the OS's own DNS servers.");
        L();
        L("5. CHANGES IT MAKES TO THE COMPUTER (only when started with --mode full, elevated; every change is recorded and removable)");
        if (OperatingSystem.IsWindows())
        {
            L("   - Windows name-resolution (NRPT) rules, one per listed name, comment \"AgantraPkiProxy\". No wildcard. Hosts file is not touched.");
            L("   - Record of the change: C:\\ProgramData\\pkiproxy\\proxy-changes.json");
        }
        else
        {
            L("   - One helper network link \"pkiproxy0\" (a dummy interface, address 192.0.2.53, reserved for documentation, never routed) and systemd-resolved routing domains ~name on it. Held in memory; nothing is written to /etc.");
            L("   - Record of the change: /var/lib/pkiproxy/proxy-changes.json");
        }
        L("   - Optional, only if the administrator runs them: --hosts-add (hosts file), --install-service / --install-systemd (a service).");
        L("     A plain-proxy service runs as a limited account (LocalService / user pkiproxy). A full-mode service (--with-dns) runs as LocalSystem / root, because changing name resolution needs those rights.");
        L("   See them:  <exe> --dns-os-status        Remove them:  <exe> --clean       (a normal stop also removes them)");
        L();
        L("6. OTHER PROGRAMS IT STARTS (fixed commands, no user input inside them)");
        L(OperatingSystem.IsWindows()
            ? "   powershell.exe -NoProfile -NonInteractive -Command ... Add-/Get-/Remove-DnsClientNrptRule, Clear-DnsClientCache   (--mode full)\n   sc.exe, icacls.exe   (only --install-service / --uninstall-service)\n   dotnet, node, java, go with a version or a name lookup   (only --env-report and --dns-test)"
            : "   resolvectl, systemctl, ip   (--mode full; ip creates and deletes the helper link)\n   systemctl, useradd and similar   (only --install-systemd / --uninstall-systemd)\n   dotnet, node, java, go, getenforce, wslinfo with a version or a name lookup   (only --env-report and --dns-test)");
        L("   It never uses -EncodedCommand or -ExecutionPolicy Bypass.");   // audit:allow(encoded-command,exec-policy) states what the program does NOT do
        L("   Child programs run without a console window of their own because their output is captured and used by the proxy.");
        L();
        L("7. FILES IT WRITES");
        L(OperatingSystem.IsWindows()
            ? "   C:\\ProgramData\\pkiproxy\\ (cache.bin, proxy-changes.json); env-report-*.txt in the current folder (--env-report); the service folder under Program Files (--install-service)."
            : "   /var/lib/pkiproxy/ (cache.bin, proxy-changes.json); env-report-*.txt in the current folder (--env-report); /opt/pkiproxy and a systemd unit (--install-systemd).");
        L();
        L("8. WHY SECURITY SOFTWARE MAY REPORT IT");
        L("   It listens on ports 53 and 80, changes DNS name-resolution rules, starts powershell.exe or systemctl, is a self-extracting single file, and may not be code-signed.");
        L("   These are the behaviours that heuristic engines score. A heuristic name such as \"Heur\" or \"Pantera\" is a score, not proof of malware.");
        L();
        L("9. WHAT TO ALLOW (narrowest first; menu names differ between product versions)");
        L("   Always: allow this one file (by SHA-256 or by exact path), or by the code-signing certificate if the file is signed. Do not exclude whole folders or drives.");
        L("   Microsoft Defender : Add a file exclusion for the exact path above (the script from --admin-script does this and checks the hash first).");
        L("                        Defender for Endpoint: a file-hash or certificate indicator (allow). If Defender is passive because another product is active, exclusions are set in that product.");
        L("   Bitdefender        : Protection > Antivirus > Settings > Exclusions: add the file path (and, if Advanced Threat Defense blocks it, the same file there). GravityZone: Policy > Antimalware > Settings > Exclusions.");
        L("   ESET               : Advanced setup > Detection engine > Performance exclusions (file path). ESET PROTECT: policy exclusion. If HIPS blocks it, add a HIPS rule for this file only.");
        L("   Other EDR          : allow-list by SHA-256 hash or by signer; allow the child process powershell.exe only when started by this file.");
        L("   False positive     : send the file to the vendor's sample / false-positive submission page. Microsoft: https://www.microsoft.com/wdsi/filesubmission");
        L("   The program does not do any of this by itself.");
        L();
        L("10. TO REMOVE EVERYTHING");
        L("   <exe> --clean   (the OS name-resolution change)   <exe> --hosts-remove   <exe> --uninstall-service | --uninstall-systemd");
        L("   Then remove the antivirus exclusion (Remove-AgantraPkiProxyAllow.ps1 from --admin-script) and delete the folder.");

        var text = T.ToString();
        Console.Write(text);
        var outFile = a.Value("out");
        if (outFile != null)
        {
            try { File.WriteAllText(outFile, text, new UTF8Encoding(false)); Console.WriteLine("Saved: " + Path.GetFullPath(outFile)); }
            catch (Exception ex) { Console.Error.WriteLine("Could not save " + outFile + ": " + ex.Message); return 1; }
        }

        if (a.Has("admin-script")) return WriteScripts(a, exe, sha);
        return 0;
    }

    static string Signer(string exe)
    {
        try
        {
#pragma warning disable SYSLIB0057   // no replacement exists for reading an Authenticode signer; only Subject/Issuer are used
            var c = X509Certificate.CreateFromSignedFile(exe);
#pragma warning restore SYSLIB0057
            return "SIGNED by " + c.Subject + " (issuer " + c.Issuer + "). Whether Windows trusts it: Get-AuthenticodeSignature <file>";
        }
        catch { return "NOT SIGNED (or the signature cannot be read here). Without a signature, allow by hash or exact path."; }
    }

    // ----- scripts for the administrator (Windows / Microsoft Defender). Written, never run. -----
    static int WriteScripts(Args a, string exe, string sha)
    {
        if (!OperatingSystem.IsWindows())
        {
            Console.WriteLine("\n--admin-script: there is no script for this OS. On Linux security products are configured in their own console; use section 9 above.");
            return 0;
        }
        string dir = a.Value("out-dir") ?? Path.Combine(Directory.GetCurrentDirectory(), "admin-handover");
        try
        {
            Directory.CreateDirectory(dir);
            string head = Header.Replace("@@PATH@@", exe.Replace("'", "''")).Replace("@@HASH@@", sha);
            File.WriteAllText(Path.Combine(dir, "Allow-AgantraPkiProxy.ps1"), head + AllowBody, new UTF8Encoding(true));
            File.WriteAllText(Path.Combine(dir, "Remove-AgantraPkiProxyAllow.ps1"), head + RemoveBody, new UTF8Encoding(true));
            Console.WriteLine("\nScripts for the administrator written to " + dir);
            Console.WriteLine("  Allow-AgantraPkiProxy.ps1         read it, then run it from an elevated PowerShell (checks the file hash first)");
            Console.WriteLine("  Remove-AgantraPkiProxyAllow.ps1   removes the exclusion again");
            Console.WriteLine("Other products (Bitdefender, ESET, other EDR) have no script: use section 9 above.");
            return 0;
        }
        catch (Exception ex) { Console.Error.WriteLine("Could not write the scripts: " + ex.Message); return 1; }
    }

    const string Header = """
        <#
        Author  : Nicko Satria Utama
        Company : Agantra Inovatif OU
        Email   : nicko@nextmantra.com

        Written by:  agantra-inovatif-crl-ocsp-proxy --admin-script
        For the ADMINISTRATOR of this computer. Read it before you run it. The proxy never runs this script itself.
        It touches only Microsoft Defender's exclusion list, and only for the one file named below.
        Other products (Bitdefender, ESET, other EDR) are configured in their own console.
        #>
        #Requires -RunAsAdministrator
        $ErrorActionPreference = 'Stop'
        $Path = '@@PATH@@'
        $ExpectedSha256 = '@@HASH@@'

        """;

    const string AllowBody = """
        if (-not (Test-Path -LiteralPath $Path)) { throw "File not found: $Path (copy the proxy there, or edit `$Path above)." }
        $actual = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($actual -ne $ExpectedSha256) {
            throw "The file does not match the hash this script was written for.`n  expected $ExpectedSha256`n  found    $actual`nDo not allow it. Compare with SHA256SUMS-proxy.txt from the release."
        }
        $sig = Get-AuthenticodeSignature -LiteralPath $Path
        Write-Host "Signature: $($sig.Status) $($sig.SignerCertificate.Subject)"
        Write-Host "Adding ONE Microsoft Defender file exclusion: $Path"
        Add-MpPreference -ExclusionPath $Path
        Write-Host 'Now excluded:'
        (Get-MpPreference).ExclusionPath | Where-Object { $_ -eq $Path }
        Write-Host 'If another security product is active, Defender is passive and this has no effect: use that product''s console.'
        """;

    const string RemoveBody = """
        Write-Host "Removing the Microsoft Defender file exclusion: $Path"
        Remove-MpPreference -ExclusionPath $Path
        Write-Host 'Done. Remaining exclusions that name this file:'
        (Get-MpPreference).ExclusionPath | Where-Object { $_ -eq $Path }
        """;
}
