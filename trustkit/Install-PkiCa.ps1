# ============================================================
# PKI Script - Install-PkiCa.ps1  (STANDALONE: needs no other script)
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OU (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
#requires -Version 5.1
<#
.SYNOPSIS
    Installs the CA certificates of the PKI (roots and intermediate CAs, NO keys) on this Windows machine. Run with .\Install-PkiCa.ps1 -Help for all details.
.DESCRIPTION
    Windows PowerShell 5.1 or PowerShell 7, Windows 10 / 11. Nothing else is needed (no OpenSSL, no other script).
    Administrator window  -> the certificates go to the machine (Local Machine) stores.
    Normal window         -> the certificates go to YOUR (Current User) stores.
    Every ROOT (top, track, quadrant) -> Trusted Root Certification Authorities.   Every INTERMEDIATE -> Intermediate Certification Authorities.
    A PKI that is already installed is replaced: the old certificates of the same organization are removed, the new ones are added.
    When it is done the extracted files are deleted (only the zip you received stays).
.EXAMPLE
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-PkiCa.ps1
.EXAMPLE
    .\Install-PkiCa.ps1 -Check          (shows what would happen, changes nothing)
#>
param(
    [string[]]$Package,
    [string]$Password,
    [ValidateSet('Auto', 'Machine', 'User')][string]$Scope = 'Auto',
    [switch]$Firefox,
    [switch]$Check,
    [switch]$Keep,
    [switch]$Help
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

function Show-Help {
@'
============================================================
 Install-PkiCa.ps1  -  install the CA certificates of the PKI on this Windows machine
 Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   Email: nicko@nextmantra.com
============================================================
Version 5.1.0

WHAT IT DOES
  Opens the .certpacked file that came in the same zip (it asks for the password) and installs the CA certificates of EVERY PKI inside it
  (a kit can hold the PKIs of several companies, for example agantra and raksaka, and several releases of each):
    * every ROOT (top root, track roots, quadrant roots)  -> Trusted Root Certification Authorities
    * every INTERMEDIATE CA                               -> Intermediate Certification Authorities
  The package holds NO private key. Nothing is signed or issued here.
  Run it in an ADMINISTRATOR window and it installs for the whole machine (Local Machine). Run it in a normal window and it installs for
  YOUR user only (Current User). Windows then asks you to confirm each root certificate: click Yes.
  The PKI is already installed (an older version)? The old certificates of the same organization are removed, the new ones are added.
  What was installed is written to a list (Local Machine: %ProgramData%\PkiTrustKit\installed.tsv, Current User: %LOCALAPPDATA%\PkiTrustKit\installed.tsv).
  To take a PKI away again use Remove-PkiCa.ps1 from the same zip:  -List, -Pki <name>, -All  (see its -Help).
  At the end the extracted files are deleted. The script and the .certpacked are deleted too, only the zip stays (-Keep keeps them).

HOW TO RUN (copy the zip to the laptop, unzip it, open PowerShell in that folder)
    powershell -NoProfile -ExecutionPolicy Bypass -File .\Install-PkiCa.ps1
  The password comes from the person who sent you the zip (by another way than the zip).
  For the whole machine: right click PowerShell -> Run as administrator, then the same command.

OPTIONS
  -Password <text>      the password (else the variable PKI_PACKAGE_PASSWORD, else you are asked)
  -Package <file,...>   the .certpacked file(s) (default: every .certpacked next to this script)
  -Scope Auto|Machine|User   Auto = Machine in an administrator window, else User. Machine without administrator = stop.
  -Firefox              also make Firefox trust the PKI (Firefox uses its own store: this sets "use the Windows certificates" in your Firefox
                        profiles; close Firefox first, start it again afterwards)
  -Check                show what would be done, change nothing
  -Keep                 do not delete the script and the .certpacked at the end
  -Help                 this text

EXIT CODES   0 done   1 error   2 administrator window needed for -Scope Machine   3 wrong password   5 this Windows is not supported

NOTES
  * Works on Windows PowerShell 5.1 and PowerShell 7. No OpenSSL, no other file of the PKI project.
  * SUPPORTED WINDOWS: Windows 11 24H2 or newer (build 26100 and later, 25H2, 26H2 ...) and Windows Server 2025: everything is installed.
    Windows Server 2022: only the CLASSIC root and intermediate CAs are installed, the post-quantum (ML-DSA) ones are left out.
    REFUSED with an error (exit 5, nothing changed): Windows 10 and earlier, Windows 11 before 24H2, Windows Server before 2022.
  * A certificate that uses a post-quantum signature (ML-DSA) is stored as it is; Windows 11 25H2 and newer also USE it, older Windows
    stores it and uses the classic ones.
  * "File cannot be loaded because running scripts is disabled": use the command above (it allows this one script).
============================================================
'@ | Write-Host
}
if ($Help) { Show-Help; return }
$script:KitVersion = '5.1.0'

function Say { param([string]$Level, [string]$Text)
    $c = 'Cyan'; if ($Level -eq 'OK') { $c = 'Green' } elseif ($Level -eq 'WARN') { $c = 'Yellow' } elseif ($Level -eq 'ERROR') { $c = 'Red' }
    Write-Host ('[{0}] {1}' -f $Level, $Text) -ForegroundColor $c
}
function Stop-Kit { param([string]$Text, [int]$Code = 1) Say 'ERROR' $Text; $script:ExitCode = $Code; throw 'PKI_KIT_STOP' }

# ---------------------------------------------------------------- the zip reader (WinZip AES and ZipCrypto; .NET Framework 4.x compatible)
$src = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

public static class PkiCaZip
{
    private static uint[] CrcTable = MakeTable();
    private static uint[] MakeTable()
    {
        uint[] t = new uint[256];
        for (uint n = 0; n < 256; n++) { uint c = n; for (int k = 0; k < 8; k++) c = ((c & 1) != 0) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1); t[n] = c; }
        return t;
    }
    private static uint CrcStep(uint crc, byte b) { return CrcTable[(crc ^ b) & 0xFF] ^ (crc >> 8); }
    private static uint Crc32(byte[] data)
    {
        uint crc = 0xFFFFFFFFu;
        for (int i = 0; i < data.Length; i++) crc = CrcStep(crc, data[i]);
        return ~crc;
    }
    private static ushort R16(byte[] b, long o) { return (ushort)(b[o] | (b[o + 1] << 8)); }
    private static uint R32(byte[] b, long o) { return (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)); }

    // PBKDF2-HMAC-SHA1 written out (the framework classes differ between Windows PowerShell 5.1 and PowerShell 7)
    private static byte[] Pbkdf2(string password, byte[] salt, int iterations, int length)
    {
        byte[] pw = Encoding.UTF8.GetBytes(password);
        int blocks = (length + 19) / 20;
        byte[] result = new byte[blocks * 20];
        using (HMACSHA1 h = new HMACSHA1(pw))
        {
            for (int b = 1; b <= blocks; b++)
            {
                byte[] sb = new byte[salt.Length + 4];
                Buffer.BlockCopy(salt, 0, sb, 0, salt.Length);
                sb[salt.Length] = (byte)(b >> 24); sb[salt.Length + 1] = (byte)(b >> 16); sb[salt.Length + 2] = (byte)(b >> 8); sb[salt.Length + 3] = (byte)b;
                byte[] u = h.ComputeHash(sb);
                byte[] t = (byte[])u.Clone();
                for (int i = 1; i < iterations; i++) { u = h.ComputeHash(u); for (int j = 0; j < 20; j++) t[j] ^= u[j]; }
                Buffer.BlockCopy(t, 0, result, (b - 1) * 20, 20);
            }
        }
        byte[] r = new byte[length];
        Buffer.BlockCopy(result, 0, r, 0, length);
        return r;
    }

    private static byte[] AesCtr(byte[] key, byte[] data)
    {
        byte[] output = new byte[data.Length];
        using (Aes aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None; aes.Key = key;
            using (ICryptoTransform enc = aes.CreateEncryptor())
            {
                byte[] counter = new byte[16]; counter[0] = 1;
                byte[] ks = new byte[16];
                for (int pos = 0; pos < data.Length; pos += 16)
                {
                    enc.TransformBlock(counter, 0, 16, ks, 0);
                    int n = Math.Min(16, data.Length - pos);
                    for (int i = 0; i < n; i++) output[pos + i] = (byte)(data[pos + i] ^ ks[i]);
                    for (int i = 0; i < 16; i++) { counter[i]++; if (counter[i] != 0) break; }
                }
            }
        }
        return output;
    }

    private class ZcKeys
    {
        public uint K0 = 0x12345678u, K1 = 0x23456789u, K2 = 0x34567890u;
        public void Update(byte c) { K0 = CrcStep(K0, c); K1 = (K1 + (K0 & 0xFF)) * 134775813u + 1u; K2 = CrcStep(K2, (byte)(K1 >> 24)); }
        public byte Next() { uint t = (K2 | 2u) & 0xFFFFu; return (byte)(((t * (t ^ 1u)) >> 8) & 0xFFu); }
        public ZcKeys(string password) { foreach (byte b in Encoding.UTF8.GetBytes(password)) Update(b); }
    }

    private class Entry
    {
        public string Name; public ushort Flags, Method, Actual, DosT; public bool Aes; public int Version, Strength;
        public uint Crc; public long CSize, USize, Offset;
    }

    private static List<Entry> ReadDirectory(byte[] a)
    {
        long eocd = -1;
        for (long i = a.Length - 22; i >= Math.Max(0, a.Length - 22 - 65535); i--) { if (R32(a, i) == 0x06054b50u) { eocd = i; break; } }
        if (eocd < 0) throw new InvalidDataException("This is not a zip archive");
        int count = R16(a, eocd + 10); long cdOff = R32(a, eocd + 16);
        List<Entry> list = new List<Entry>();
        long p = cdOff;
        for (int n = 0; n < count; n++)
        {
            if (R32(a, p) != 0x02014b50u) throw new InvalidDataException("Damaged archive (central directory)");
            Entry e = new Entry();
            e.Flags = R16(a, p + 8); e.Method = R16(a, p + 10); e.DosT = R16(a, p + 12);
            e.Crc = R32(a, p + 16); e.CSize = R32(a, p + 20); e.USize = R32(a, p + 24);
            int nl = R16(a, p + 28), el = R16(a, p + 30), cl = R16(a, p + 32);
            e.Offset = R32(a, p + 42);
            e.Name = Encoding.UTF8.GetString(a, (int)(p + 46), nl);
            e.Actual = e.Method;
            long x = p + 46 + nl, xe = x + el;
            while (x + 4 <= xe)
            {
                int id = R16(a, x), sz = R16(a, x + 2);
                if (id == 0x9901 && sz >= 7) { e.Aes = true; e.Version = R16(a, x + 4); e.Strength = a[x + 8]; e.Actual = R16(a, x + 9); }
                x += 4 + sz;
            }
            list.Add(e);
            p += 46 + nl + el + cl;
        }
        return list;
    }

    private static byte[] ReadEntry(byte[] a, Entry e, string password)
    {
        long o = e.Offset;
        if (R32(a, o) != 0x04034b50u) throw new InvalidDataException("Damaged archive (local header of " + e.Name + ")");
        long start = o + 30 + R16(a, o + 26) + R16(a, o + 28);
        byte[] raw = new byte[e.CSize];
        Buffer.BlockCopy(a, (int)start, raw, 0, (int)e.CSize);
        byte[] comp;
        bool checkCrc = true;
        if ((e.Flags & 1) == 0 && !e.Aes) { comp = raw; }
        else if (e.Aes)
        {
            int keyLen = e.Strength == 3 ? 32 : (e.Strength == 2 ? 24 : 16), saltLen = keyLen / 2;
            if (raw.Length < saltLen + 2 + 10) throw new InvalidDataException("Damaged archive (" + e.Name + ")");
            byte[] salt = new byte[saltLen]; Buffer.BlockCopy(raw, 0, salt, 0, saltLen);
            byte[] km = Pbkdf2(password, salt, 1000, 2 * keyLen + 2);
            byte[] ek = new byte[keyLen]; byte[] ak = new byte[keyLen];
            Buffer.BlockCopy(km, 0, ek, 0, keyLen); Buffer.BlockCopy(km, keyLen, ak, 0, keyLen);
            if (raw[saltLen] != km[2 * keyLen] || raw[saltLen + 1] != km[2 * keyLen + 1]) throw new UnauthorizedAccessException("WRONG_PASSWORD");
            int clen = raw.Length - saltLen - 2 - 10;
            byte[] ct = new byte[clen]; Buffer.BlockCopy(raw, saltLen + 2, ct, 0, clen);
            byte[] mac = new byte[10]; Buffer.BlockCopy(raw, saltLen + 2 + clen, mac, 0, 10);
            byte[] full;
            using (HMACSHA1 h = new HMACSHA1(ak)) { full = h.ComputeHash(ct); }
            int diff = 0; for (int i = 0; i < 10; i++) diff |= (mac[i] ^ full[i]);
            if (diff != 0) throw new InvalidDataException("The package is damaged or was changed (" + e.Name + ")");
            comp = AesCtr(ek, ct);
            if (e.Version == 2) checkCrc = false;
        }
        else
        {
            if (raw.Length < 12) throw new InvalidDataException("Damaged archive (" + e.Name + ")");
            ZcKeys k = new ZcKeys(password);
            byte[] plain = new byte[raw.Length - 12];
            byte last = 0;
            for (int i = 0; i < raw.Length; i++)
            {
                byte p = (byte)(raw[i] ^ k.Next()); k.Update(p);
                if (i < 12) last = p; else plain[i - 12] = p;
            }
            byte expect = ((e.Flags & 8) != 0) ? (byte)(e.DosT >> 8) : (byte)(e.Crc >> 24);
            if (last != expect) throw new UnauthorizedAccessException("WRONG_PASSWORD");
            comp = plain;
        }
        byte[] data;
        if (e.Actual == 8)
        {
            using (MemoryStream srcMs = new MemoryStream(comp))
            using (DeflateStream ds = new DeflateStream(srcMs, CompressionMode.Decompress))
            using (MemoryStream dst = new MemoryStream()) { ds.CopyTo(dst); data = dst.ToArray(); }
        }
        else if (e.Actual == 0) { data = comp; }
        else throw new NotSupportedException("Compression method " + e.Actual + " is not supported");
        if (data.Length != e.USize) throw new InvalidDataException("Damaged archive (size of " + e.Name + ")");
        if (checkCrc && Crc32(data) != e.Crc) throw new UnauthorizedAccessException("WRONG_PASSWORD");
        return data;
    }

    // writes the entries whose name starts with one of the prefixes into destDir; returns how many
    public static int Extract(string archivePath, string destDir, string password, string[] prefixes)
    {
        byte[] a = File.ReadAllBytes(archivePath);
        string root = Path.GetFullPath(destDir);
        int n = 0;
        foreach (Entry e in ReadDirectory(a))
        {
            string name = e.Name.Replace('\\', '/');
            if (name.EndsWith("/")) continue;
            bool hit = false;
            foreach (string p in prefixes) { if (name.StartsWith(p, StringComparison.OrdinalIgnoreCase)) { hit = true; break; } }
            if (!hit) continue;
            if (name.IndexOf(':') >= 0 || name.StartsWith("/") || ("/" + name + "/").Contains("/../")) throw new InvalidDataException("Unsafe name in the package: " + name);
            string full = Path.GetFullPath(Path.Combine(root, name.Replace('/', Path.DirectorySeparatorChar)));
            if (!full.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.Ordinal)) throw new InvalidDataException("Unsafe name in the package: " + name);
            byte[] data = ReadEntry(a, e, password);
            Directory.CreateDirectory(Path.GetDirectoryName(full));
            File.WriteAllBytes(full, data);
            n++;
        }
        return n;
    }
}
'@

$script:ExitCode = 0
$work = $null
$done = $false
try {
    Write-Host '============================================================'
    Write-Host ' Install-PkiCa.ps1 - CA certificates of the PKI (no keys)'
    Write-Host ' Author : Nicko Satria Utama   Company: Agantra Inovatif OU (NextMantra)   nicko@nextmantra.com'
    Write-Host '============================================================'

    # ---- 1. this machine
    $isWin = ([Environment]::OSVersion.Platform -eq [PlatformID]::Win32NT)
    if (-not $isWin) { Say 'WARN' 'This is not Windows: test mode (the certificates go to the .NET store of this user). On Linux use install-pki-ca.sh.' }

    # ---- 1a. which Windows? Supported: Windows 11 24H2 or newer (build 26100+), Windows Server 2025 (build 26100+: everything),
    #          Windows Server 2022 (build 20348..26099: CLASSIC certificates only, the post-quantum ones are skipped). Everything else is refused.
    $osMode = 'full'; $osName = ''
    $osKind = ''; $osBuild = 0; $osProduct = ''; $osEd = ''
    if ($isWin) {
        try {
            $cv = Get-ItemProperty -LiteralPath 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion' -ErrorAction Stop
            $osBuild = [int]$cv.CurrentBuildNumber; $osProduct = [string]$cv.ProductName
            $osKind = [string]$cv.InstallationType            # Client | Server | Server Core
            $osEd = [string]$cv.EditionID
        } catch { $osBuild = [Environment]::OSVersion.Version.Build }
    }
    if ($env:PKI_FAKE_OS) { $fp = $env:PKI_FAKE_OS.Split(':'); $osKind = $fp[0]; $osBuild = [int]$fp[1]; $osProduct = 'test (PKI_FAKE_OS)'; $osEd = $(if ($fp.Count -gt 2) { $fp[2] } elseif ($osKind -like 'Server*') { 'ServerStandard' } else { 'Professional' }) }   # for tests only (Kind:Build[:EditionID])
    if ($isWin -or $env:PKI_FAKE_OS) {
        $isServer = ($osKind -like 'Server*')
        $osName = if ($osProduct) { "$osProduct (build $osBuild)" } else { "Windows build $osBuild" }
        if ($osEd) { $osName = "$osName, edition $osEd" }
        # specialised editions are refused in every version (Chinese, Government, IoT / IoT Enterprise, SE, Embedded)
        $osText = "$osEd $osProduct"
        $osBad = if ($osText -match '(?i)china|chinese|CountrySpecific') { 'a Chinese edition' } elseif ($osText -match '(?i)government|EnterpriseG\b|EnterpriseGN|\bGov\b') { 'a Government edition' } elseif ($osText -match '(?i)IoT') { 'an IoT / IoT Enterprise edition' } elseif ($osText -match '(?i)Embedded') { 'an Embedded edition' } elseif ($osEd -match '(?i)^Cloud' -or $osProduct -match '(?i)\bSE\b') { 'Windows 11 SE' } else { '' }
        if ($osBad) { Stop-Kit "This computer is ${osName}: $osBad. Specialised Windows editions are NOT supported (supported: Windows 11 Home / Pro / Pro for Workstations / Education / Pro Education / Enterprise 24H2 or newer, Windows Server 2025, Windows Server 2022). Nothing was changed." 5 }
        if ($isServer) {
            if ($osEd -and $osEd -notmatch '^Server(Standard|Datacenter|Solution|Essentials)(Core|Eval|ACor)?$') { Stop-Kit "This computer is ${osName}: this Windows Server edition is NOT supported (Essentials, Standard, Datacenter only). Nothing was changed." 5 }
            if ($osBuild -ge 26100) { $osMode = 'full' }
            elseif ($osBuild -ge 20348 -and $osBuild -lt 22000) { $osMode = 'classic' }
            elseif ($osBuild -ge 20348) { Stop-Kit "This computer is ${osName}: this Windows Server build is NOT supported (only Windows Server 2022 RTM and Windows Server 2025). Nothing was changed." 5 }
            else { Stop-Kit "This computer is ${osName}. A Windows Server before 2022 is NOT supported (supported: Windows Server 2022 with the classic certificates only, Windows Server 2025, Windows 11 24H2 or newer). Nothing was changed." 5 }
        }
        else {
            if ($osBuild -lt 22000) { Stop-Kit "This computer is ${osName}: Windows 10 and earlier are NOT supported (supported: Windows 11 24H2 or newer, Windows Server 2025, Windows Server 2022 with the classic certificates only). Nothing was changed." 5 }
            if ($osEd -and $osEd -notmatch '^(Core|CoreN|CoreSingleLanguage|Professional|ProfessionalN|ProfessionalWorkstation|ProfessionalWorkstationN|ProfessionalEducation|ProfessionalEducationN|Education|EducationN|Enterprise|EnterpriseN)$') { Stop-Kit "This computer is ${osName}: this Windows edition is NOT supported (Home, Pro, Pro for Workstations, Education, Pro Education, Enterprise). Nothing was changed." 5 }
            if ($osBuild -lt 26100) { Stop-Kit "This computer is ${osName}: Windows 11 before 24H2 is NOT supported (needs Windows 11 24H2 = build 26100 or newer). Nothing was changed." 5 }
        }
        Say 'INFO' ("Install-PkiCa.ps1 version $script:KitVersion")
        Say 'INFO' ("Windows: {0} - {1}" -f $osName, $(if ($osMode -eq 'classic') { 'Windows Server 2022: only the CLASSIC certificates are installed (the post-quantum ones are skipped)' } else { 'supported, all certificates are installed' }))
    }

    $admin = $false
    if ($isWin) {
        $wid = [Security.Principal.WindowsIdentity]::GetCurrent()
        $admin = (New-Object Security.Principal.WindowsPrincipal($wid)).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    }
    $machine = $false
    if ($Scope -eq 'Machine') { $machine = $true } elseif ($Scope -eq 'Auto') { $machine = $admin }
    if ($machine -and -not $admin) { Stop-Kit 'Scope Machine needs an administrator window: right click PowerShell -> Run as administrator, then run this script again.' 2 }
    $loc = 'CurrentUser'; $locText = 'Current User (this user only)'
    if ($machine) { $loc = 'LocalMachine'; $locText = 'Local Machine (every user of this computer)' }
    Say 'INFO' ("PowerShell {0}, {1}. Installing for: {2}" -f $PSVersionTable.PSVersion, $(if ($admin) { 'administrator window' } else { 'normal window' }), $locText)
    if (-not $machine -and $isWin) { Say 'INFO' 'Windows will ask you to confirm each root certificate (a security warning): click Yes. For the whole machine run this in an administrator window.' }
    if ($Check) { Say 'INFO' 'CHECK mode: nothing is changed.' }

    # ---- 2. the package and the password
    $here = Split-Path -Parent $MyInvocation.MyCommand.Path
    if (-not $Package) {
        $found = @(Get-ChildItem -LiteralPath $here -Filter '*.certpacked' -File -ErrorAction SilentlyContinue)      # one .certpacked holds ALL the PKIs of the kit (older kits: one per PKI)
        if ($found.Count -eq 0) { Stop-Kit "No .certpacked file next to this script ($here). Unzip the whole zip first, or use -Package <file>." }
        $Package = @($found | Sort-Object Name | ForEach-Object { $_.FullName })      # several = a kit of ALL releases: every one is installed
    }
    $pk = @()
    foreach ($one in @($Package)) {
        if (-not (Test-Path -LiteralPath $one -PathType Leaf)) { Stop-Kit "Package not found: $one" }
        $pk += (Resolve-Path -LiteralPath $one).Path
    }
    $Package = $pk
    $pw = $Password
    if (-not $pw) { $pw = $env:PKI_PACKAGE_PASSWORD }
    if (-not $pw) {
        $sec = Read-Host -Prompt 'Password of the package (from the person who sent you the zip)' -AsSecureString
        $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($sec)
        try { $pw = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr) } finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    }
    if (-not $pw) { Stop-Kit 'No password.' 3 }

    # ---- 3. open it into a temporary folder (deleted at the end)
    if (-not ('PkiCaZip' -as [type])) { Add-Type -TypeDefinition $src -Language CSharp }
    $work = Join-Path ([IO.Path]::GetTempPath()) ('pki-ca-' + [guid]::NewGuid().ToString('N').Substring(0, 12))
    [void](New-Item -ItemType Directory -Path $work -Force)
    $n = 0; $pkIndex = 0; $tsvList = @()
    foreach ($onePackage in $Package) {
        $pkIndex++
        $sub = Join-Path $work ('p' + $pkIndex)
        [void](New-Item -ItemType Directory -Path $sub -Force)
        try { $n += [PkiCaZip]::Extract($onePackage, $sub, $pw, @('ca/roots/', 'ca/intermediates/', 'certpack.tsv')) }
        catch {
            $m = $_.Exception.Message
            if ($_.Exception.InnerException) { $m = $_.Exception.InnerException.Message }
            if ($m -like '*WRONG_PASSWORD*') { Stop-Kit 'The password is wrong.' 3 }
            Stop-Kit "The package cannot be opened ($(Split-Path -Leaf $onePackage)): $m"
        }
        $tp = Join-Path $sub 'certpack.tsv'
        if (-not (Test-Path -LiteralPath $tp)) { Stop-Kit "This is not a PKI package (certpack.tsv is missing): $(Split-Path -Leaf $onePackage)" }
        $tsvList += , @($tp, $sub)
    }
    Say 'OK' ("{0} package(s) opened ({1} files)." -f @($Package).Count, $n)

    # ---- 4. the list of CA certificates, checked against their SHA-256
    $sha = [Security.Cryptography.SHA256]::Create()
    $roots = New-Object System.Collections.ArrayList
    $inter = New-Object System.Collections.ArrayList
    $seenThumb = @{}
    foreach ($tsvEntry in $tsvList) {
    $tsvPath = $tsvEntry[0]; $pkgDir = $tsvEntry[1]
    foreach ($line in (Get-Content -LiteralPath $tsvPath -Encoding UTF8)) {
        if (-not $line -or $line.StartsWith('#')) { continue }
        $f = $line.Split("`t")
        if ($f.Count -lt 3) { continue }
        $role = $f[0]; $rel = $f[1]; $want = $f[2].ToLowerInvariant()
        if ($role -ne 'root' -and $role -ne 'intermediate') { continue }
        $full = Join-Path $pkgDir ($rel -replace '/', [IO.Path]::DirectorySeparatorChar)
        if (-not (Test-Path -LiteralPath $full)) { Stop-Kit "Missing in the package: $rel" }
        $bytes = [IO.File]::ReadAllBytes($full)
        $got = ([BitConverter]::ToString($sha.ComputeHash($bytes))).Replace('-', '').ToLowerInvariant()
        if ($got -ne $want) { Stop-Kit "Checksum mismatch (the package was changed or damaged): $rel" }
        $cert = New-Object Security.Cryptography.X509Certificates.X509Certificate2(, $bytes)
        $seenKey = $role + ':' + $cert.Thumbprint.ToUpperInvariant()
        if ($seenThumb.ContainsKey($seenKey)) { continue }      # the same certificate in two releases: once is enough
        $seenThumb[$seenKey] = $true
        $org = ''
        if ($cert.Subject -match '(?:^|,\s*)O=(?<o>"[^"]*"|[^,]+)') { $org = $Matches['o'].Trim('"').Trim() }
        $pkiTag = ''; $relTag = ''
        if ($f.Count -gt 9 -and $f[9]) { $pkiTag = $f[9].Trim() }          # kits made since 5.1.0 carry the company and the PKI folder of every certificate
        if ($f.Count -gt 10 -and $f[10]) { $relTag = $f[10].Trim() }
        if (-not $pkiTag -and $org) { $pkiTag = ($org -split '[^A-Za-z0-9]+' | Where-Object { $_ } | Select-Object -First 1).ToLowerInvariant() }
        $item = New-Object psobject -Property @{ Cert = $cert; Thumb = $cert.Thumbprint.ToUpperInvariant(); Org = $org; Name = $cert.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false); Role = $role; Pki = $pkiTag; Release = $relTag }
        if ($role -eq 'root') { [void]$roots.Add($item) } else { [void]$inter.Add($item) }
    }
    }
    if ($osMode -eq 'classic') {
        # Windows Server 2022 cannot use post-quantum signatures (ML-DSA, SLH-DSA, OIDs 2.16.840.1.101.3.4.3.17 - .31): leave these certificates out
        $isPq = { param($i) $o = [string]$i.Cert.SignatureAlgorithm.Value; $o -match '^2\.16\.840\.1\.101\.3\.4\.3\.(1[7-9]|2[0-9]|3[01])$' }
        $skipRoots = @($roots | Where-Object { & $isPq $_ }); $skipInter = @($inter | Where-Object { & $isPq $_ })
        $keepRoots = New-Object System.Collections.ArrayList; foreach ($i in $roots) { if (-not (& $isPq $i)) { [void]$keepRoots.Add($i) } }
        $keepInter = New-Object System.Collections.ArrayList; foreach ($i in $inter) { if (-not (& $isPq $i)) { [void]$keepInter.Add($i) } }
        $roots = $keepRoots; $inter = $keepInter
        Say 'WARN' ("Windows Server 2022: {0} post-quantum root(s) and {1} post-quantum intermediate(s) are NOT installed (only the classic PKI is installed)." -f $skipRoots.Count, $skipInter.Count)
    }
    if ($roots.Count -eq 0) { Stop-Kit 'No root certificate in the package.' }
    $orgs = @{}
    foreach ($i in (@($roots) + @($inter))) { if ($i.Org) { $orgs[$i.Org] = $true } }
    if ($orgs.Count -eq 0) { Stop-Kit 'The certificates have no organization name: the old version cannot be recognized. Stopped, nothing was changed.' }
    Say 'OK' ("{0} root and {1} intermediate certificate(s), checksums fine. Organization: {2}" -f $roots.Count, $inter.Count, (($orgs.Keys | Sort-Object) -join ', '))
    $pkiSet = @{}; foreach ($i in (@($roots) + @($inter))) { $k = if ($i.Release) { $i.Pki + ' / ' + $i.Release } else { $i.Pki }; if (-not $pkiSet.ContainsKey($k)) { $pkiSet[$k] = 0 }; $pkiSet[$k]++ }
    foreach ($k in ($pkiSet.Keys | Sort-Object)) { Say 'INFO' ("  PKI {0}: {1} CA certificate(s)" -f $k, $pkiSet[$k]) }

    # ---- 5. the stores
    $storeRoot = 'Root'; $storeCa = 'CA'
    function Open-PkiStore { param([string]$Name, [bool]$Write)
        $s = New-Object Security.Cryptography.X509Certificates.X509Store($Name, $loc)
        $flag = [Security.Cryptography.X509Certificates.OpenFlags]::ReadOnly
        if ($Write) { $flag = [Security.Cryptography.X509Certificates.OpenFlags]::ReadWrite }
        $s.Open($flag)
        return $s
    }
    function Get-StoreThumbs { param([string]$Name)
        $s = Open-PkiStore $Name $false
        try { $h = @{}; foreach ($c in $s.Certificates) { $h[$c.Thumbprint.ToUpperInvariant()] = $c }; return $h } finally { $s.Close() }
    }
    function Get-Org { param($Cert) $o = ''; if ($Cert.Subject -match '(?:^|,\s*)O=(?<o>"[^"]*"|[^,]+)') { $o = $Matches['o'].Trim('"').Trim() }; return $o }

    $plan = @(
        @{ Store = $storeRoot; Label = 'Trusted Root Certification Authorities'; Items = @($roots) },
        @{ Store = $storeCa;   Label = 'Intermediate Certification Authorities'; Items = @($inter) }
    )
    $removed = 0; $added = 0; $kept = 0; $removedThumbs = @()
    foreach ($p in $plan) {
        $have = Get-StoreThumbs $p.Store
        $newThumbs = @{}; foreach ($i in $p.Items) { $newThumbs[$i.Thumb] = $true }
        # old version = same organization, not in this package
        $old = @()
        foreach ($t in $have.Keys) { if (-not $newThumbs.ContainsKey($t)) { $o = Get-Org $have[$t]; if ($o -and $orgs.ContainsKey($o)) { $old += $have[$t] } } }
        Say 'INFO' ("{0} ({1}): {2} in this package, {3} old certificate(s) of the same organization to replace." -f $p.Label, $p.Store, @($p.Items).Count, $old.Count)
        if (-not $Check) {
            $s = Open-PkiStore $p.Store $true
            try {
                foreach ($c in $old) { $s.Remove($c); $removed++; $removedThumbs += $c.Thumbprint.ToUpperInvariant(); Say 'OK' ("  removed old: " + $c.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)) }
                foreach ($i in $p.Items) {
                    if ($have.ContainsKey($i.Thumb)) { $kept++; continue }
                    $s.Add($i.Cert); $added++; Say 'OK' ("  installed: " + $i.Name)
                }
            } finally { $s.Close() }
        } else {
            foreach ($c in $old) { Say 'INFO' ("  would remove: " + $c.GetNameInfo([Security.Cryptography.X509Certificates.X509NameType]::SimpleName, $false)) }
            foreach ($i in $p.Items) { if (-not $have.ContainsKey($i.Thumb)) { Say 'INFO' ("  would install: " + $i.Name) } }
        }
    }

    # ---- 6. read back
    if (-not $Check) {
        $missing = 0
        foreach ($p in $plan) { $have = Get-StoreThumbs $p.Store; foreach ($i in $p.Items) { if (-not $have.ContainsKey($i.Thumb)) { $missing++; Say 'ERROR' ("not in the store: " + $i.Name) } } }
        if ($missing -gt 0) { Stop-Kit "$missing certificate(s) are NOT in the store (a confirmation window answered No?). Run the script again." }
        Say 'OK' ("Checked: all {0} certificate(s) are in the {1} store ({2} installed now, {3} were already there, {4} old removed)." -f (@($roots).Count + @($inter).Count), $loc, $added, $kept, $removed)
    }

    # ---- 6b. remember what this kit installed (Remove-PkiCa.ps1 uses it): one line per certificate
    if (-not $Check) {
        try {
            $stateDir = $env:PKI_KIT_STATE_DIR
            if (-not $stateDir) { if ($machine) { $stateDir = Join-Path $(if ($env:ProgramData) { $env:ProgramData } else { '/var/lib' }) 'PkiTrustKit' } else { $stateDir = Join-Path $(if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { Join-Path $HOME '.local/share' }) 'PkiTrustKit' } }
            [void](New-Item -ItemType Directory -Path $stateDir -Force)
            $reg = Join-Path $stateDir 'installed.tsv'
            $scopeName = if ($machine) { 'Machine' } else { 'User' }
            $regKeep = @()
            if (Test-Path -LiteralPath $reg) {
                $newT = @{}; foreach ($i in (@($roots) + @($inter))) { $newT[$i.Thumb] = $true }
                foreach ($l in (Get-Content -LiteralPath $reg -Encoding UTF8)) { if (-not $l -or $l.StartsWith('#')) { continue }; $c = $l.Split("`t"); if ($c.Count -ge 4 -and -not $newT.ContainsKey($c[3]) -and ($removedThumbs -notcontains $c[3])) { $regKeep += $l } }
            }
            $now = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
            $rows = @('# pki' + "`t" + 'release' + "`t" + 'store' + "`t" + 'thumbprint' + "`t" + 'name' + "`t" + 'organization' + "`t" + 'scope' + "`t" + 'installedUtc') + $regKeep
            foreach ($p in $plan) { foreach ($i in $p.Items) { $rows += (@($i.Pki, $i.Release, $p.Store, $i.Thumb, $i.Name, $i.Org, $scopeName, $now) -join "`t") } }
            [IO.File]::WriteAllLines($reg, [string[]]$rows)
            Say 'INFO' ("Remembered in {0} (Remove-PkiCa.ps1 -List shows it; -Pki <name> or -All removes)." -f $reg)
        } catch { Say 'WARN' ("Could not write the list of installed PKIs ({0}); Remove-PkiCa.ps1 -Org <organization> still works." -f $_.Exception.Message) }
    }

    # ---- 7. Firefox (optional)
    if ($Firefox) {
        $profRoot = ''
        if ($env:APPDATA) { $profRoot = Join-Path $env:APPDATA 'Mozilla\Firefox\Profiles' }
        elseif ($env:HOME) { $profRoot = Join-Path $env:HOME '.mozilla/firefox' }
        $profiles = @()
        if ($profRoot -and (Test-Path -LiteralPath $profRoot)) { $profiles = @(Get-ChildItem -LiteralPath $profRoot -Directory | Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName 'prefs.js') }) }
        if ($profiles.Count -eq 0) { Say 'WARN' 'Firefox: no profile found (start Firefox once, then run this script again with -Firefox).' }
        else {
            if (Get-Process -Name firefox -ErrorAction SilentlyContinue) { Say 'WARN' 'Firefox is running: close it and start it again after this script.' }
            $pref = 'user_pref("security.enterprise_roots.enabled", true);'
            foreach ($pr in $profiles) {
                $uj = Join-Path $pr.FullName 'user.js'
                $text = ''; if (Test-Path -LiteralPath $uj) { $text = [IO.File]::ReadAllText($uj) }
                if ($text -match 'security\.enterprise_roots\.enabled') { Say 'INFO' ("Firefox profile {0}: already set." -f $pr.Name); continue }
                if ($Check) { Say 'INFO' ("Firefox profile {0}: would be set." -f $pr.Name); continue }
                [IO.File]::AppendAllText($uj, ($pref + "`r`n"))
                Say 'OK' ("Firefox profile {0}: Firefox now uses the Windows certificates." -f $pr.Name)
            }
        }
    }
    $done = (-not $Check)
}
catch {
    if ($_.Exception.Message -ne 'PKI_KIT_STOP') { Say 'ERROR' $_.Exception.Message; $script:ExitCode = 1 }
}
finally {
    # the extracted files never stay
    if ($work -and (Test-Path -LiteralPath $work)) { try { Remove-Item -LiteralPath $work -Recurse -Force -ErrorAction Stop; Say 'INFO' 'The extracted files were deleted.' } catch { Say 'WARN' "Could not delete $work : delete it by hand." } }
}

if ($done -and $script:ExitCode -eq 0) {
    if (-not $Keep) {
        # only the zip you received stays: this script and the .certpacked go, and the folder when it is the folder made from the zip
        try {
            $self = $MyInvocation.MyCommand.Path
            $dir = Split-Path -Parent $self
            foreach ($onePackage in @($Package)) { if (Test-Path -LiteralPath $onePackage) { Remove-Item -LiteralPath $onePackage -Force } }
            Remove-Item -LiteralPath $self -Force
            if ((Split-Path -Leaf $dir) -match '^windows-pki-' -and @(Get-ChildItem -LiteralPath $dir -Force).Count -eq 0) { Set-Location -LiteralPath (Split-Path -Parent $dir); Remove-Item -LiteralPath $dir -Force }
            Say 'INFO' 'Removed this script and the package (only the zip stays). -Keep keeps them next time.'
        } catch { Say 'WARN' 'Could not remove this script / the package: delete the unzipped folder by hand.' }
    }
    Say 'OK' 'Done. Restart your browser / Office / tools so they read the new certificates.'
}
exit $script:ExitCode
