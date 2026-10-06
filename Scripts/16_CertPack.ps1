# ============================================================
# PKI Script
# Author : Nicko Satria Utama
# Company: Agantra Inovatif OÜ (NextMantra)
# Email  : nicko@nextmantra.com
# ============================================================
# 16_CertPack.ps1  -  the password-protected archive layer of the transport (".certpacked")
#
# A .certpacked file IS a password-protected archive under another name. Rename it to .zip or .7z and any
# 7-Zip compatible program opens it with the password. Three kinds:
#
#   zip + AES-256   (default)  WinZip AES (AE-2): PBKDF2-HMAC-SHA1, AES-256-CTR, HMAC-SHA1 authentication of every
#                              entry. Made and read by THIS module with .NET only: no 7-Zip on Windows needed.
#                              Linux / macOS: 7-Zip (7z, 7zz, 7za) reads it; pki-transport.sh installs it if it can.
#   zip + ZipCrypto (legacy)   The old PKWARE encryption: weak against known-plaintext attacks. Only for packages
#                              that carry nothing secret (CA certificates). Plain "unzip -P" reads it everywhere.
#   7z  + AES-256              LZMA2 with encrypted headers (file names hidden). Needs 7-Zip to make and to read.
#
# The kind is found from the first bytes of the file, never from the extension.
#
# Provides : Initialize-PkiZipLibrary, Get-PkiArchiveType, New-PkiAesZipArchive, Expand-PkiAesZipArchive,
#            Get-PkiAesZipEntries, Find-PkiSevenZip, New-PkiSevenZipArchive, Expand-PkiSevenZipArchive,
#            Expand-PkiArchive, Test-PkiArchivePassword
# Requires : 00_Common
# ============================================================
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$script:PkiZipSource = @'
using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;

public static class PkiZip
{
    // ---------------------------------------------------------------- CRC-32
    private static readonly uint[] CrcTable = MakeTable();
    private static uint[] MakeTable()
    {
        var t = new uint[256];
        for (uint n = 0; n < 256; n++) { uint c = n; for (int k = 0; k < 8; k++) c = ((c & 1) != 0) ? (0xEDB88320u ^ (c >> 1)) : (c >> 1); t[n] = c; }
        return t;
    }
    public static uint Crc32(byte[] data)
    {
        uint crc = 0xFFFFFFFFu;
        for (int i = 0; i < data.Length; i++) crc = CrcTable[(crc ^ data[i]) & 0xFF] ^ (crc >> 8);
        return ~crc;
    }
    private static uint CrcStep(uint crc, byte b) { return CrcTable[(crc ^ b) & 0xFF] ^ (crc >> 8); }

    // ---------------------------------------------------------------- WinZip AES
    private static void AesKeys(string password, byte[] salt, int keyLen, out byte[] encKey, out byte[] authKey, out byte[] pwv)
    {
        byte[] pw = Encoding.UTF8.GetBytes(password);
        byte[] km = Rfc2898DeriveBytes.Pbkdf2(pw, salt, 1000, HashAlgorithmName.SHA1, 2 * keyLen + 2);
        encKey = new byte[keyLen]; authKey = new byte[keyLen]; pwv = new byte[2];
        Buffer.BlockCopy(km, 0, encKey, 0, keyLen);
        Buffer.BlockCopy(km, keyLen, authKey, 0, keyLen);
        Buffer.BlockCopy(km, 2 * keyLen, pwv, 0, 2);
    }

    // AES-CTR with a LITTLE-endian counter that starts at 1 (the WinZip way; not the OpenSSL way)
    private static byte[] AesCtr(byte[] key, byte[] data)
    {
        byte[] output = new byte[data.Length];
        using (var aes = Aes.Create())
        {
            aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None; aes.Key = key;
            using (var enc = aes.CreateEncryptor())
            {
                byte[] counter = new byte[16]; counter[0] = 1;
                byte[] ks = new byte[16];
                for (int pos = 0; pos < data.Length; pos += 16)
                {
                    enc.TransformBlock(counter, 0, 16, ks, 0);
                    int n = Math.Min(16, data.Length - pos);
                    for (int i = 0; i < n; i++) output[pos + i] = (byte)(data[pos + i] ^ ks[i]);
                    for (int i = 0; i < 16; i++) { if (++counter[i] != 0) break; }
                }
            }
        }
        return output;
    }

    private static byte[] Mac(byte[] authKey, byte[] cipher)
    {
        using (var h = new HMACSHA1(authKey)) { byte[] full = h.ComputeHash(cipher); byte[] t = new byte[10]; Buffer.BlockCopy(full, 0, t, 0, 10); return t; }
    }

    // ---------------------------------------------------------------- ZipCrypto (legacy)
    private sealed class ZcKeys
    {
        public uint K0 = 0x12345678u, K1 = 0x23456789u, K2 = 0x34567890u;
        public void Update(byte c)
        {
            K0 = CrcStep(K0, c);
            K1 = (K1 + (K0 & 0xFF)) * 134775813u + 1u;
            K2 = CrcStep(K2, (byte)(K1 >> 24));
        }
        public byte Next() { uint t = (K2 | 2u) & 0xFFFFu; return (byte)(((t * (t ^ 1u)) >> 8) & 0xFFu); }
        public ZcKeys(string password) { foreach (byte b in Encoding.UTF8.GetBytes(password)) Update(b); }
    }
    private static byte[] ZcEncrypt(byte[] data, string password, uint crc)
    {
        var k = new ZcKeys(password);
        byte[] header = new byte[12];
        byte[] rnd = new byte[11]; RandomNumberGenerator.Fill(rnd);
        Buffer.BlockCopy(rnd, 0, header, 0, 11);
        header[11] = (byte)(crc >> 24);
        byte[] outp = new byte[12 + data.Length];
        for (int i = 0; i < 12; i++) { byte p = header[i]; outp[i] = (byte)(p ^ k.Next()); k.Update(p); }
        for (int i = 0; i < data.Length; i++) { byte p = data[i]; outp[12 + i] = (byte)(p ^ k.Next()); k.Update(p); }
        return outp;
    }

    // ---------------------------------------------------------------- helpers
    private static void U16(Stream s, int v) { s.WriteByte((byte)v); s.WriteByte((byte)(v >> 8)); }
    private static void U32(Stream s, uint v) { s.WriteByte((byte)v); s.WriteByte((byte)(v >> 8)); s.WriteByte((byte)(v >> 16)); s.WriteByte((byte)(v >> 24)); }
    private static ushort R16(byte[] b, long o) { return (ushort)(b[o] | (b[o + 1] << 8)); }
    private static uint R32(byte[] b, long o) { return (uint)(b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)); }

    private static void DosTime(DateTime t, out ushort time, out ushort date)
    {
        if (t.Year < 1980) t = new DateTime(1980, 1, 1);
        time = (ushort)((t.Hour << 11) | (t.Minute << 5) | (t.Second / 2));
        date = (ushort)(((t.Year - 1980) << 9) | (t.Month << 5) | t.Day);
    }
    private static DateTime FromDos(ushort time, ushort date)
    {
        try { return new DateTime(((date >> 9) & 0x7F) + 1980, Math.Max(1, (date >> 5) & 0x0F), Math.Max(1, date & 0x1F), (time >> 11) & 0x1F, (time >> 5) & 0x3F, (time & 0x1F) * 2); }
        catch { return DateTime.Now; }
    }

    // ---------------------------------------------------------------- Create
    public static void Create(string archivePath, string[] sources, string[] names, string password, string encryption)
    {
        if (sources.Length != names.Length) throw new ArgumentException("sources and names differ in length");
        bool aes = !string.Equals(encryption, "ZipCrypto", StringComparison.OrdinalIgnoreCase);
        if (string.IsNullOrEmpty(password)) throw new ArgumentException("A password is required");
        var central = new List<byte[]>();
        using (var fs = new FileStream(archivePath, FileMode.Create, FileAccess.Write))
        {
            for (int i = 0; i < sources.Length; i++)
            {
                byte[] data = File.ReadAllBytes(sources[i]);
                string name = names[i].Replace('\\', '/').TrimStart('/');
                byte[] nameBytes = Encoding.UTF8.GetBytes(name);
                ushort dt, dd; DosTime(File.GetLastWriteTime(sources[i]), out dt, out dd);
                uint crc = Crc32(data);

                byte[] comp; ushort actual = 8;
                using (var ms = new MemoryStream())
                {
                    using (var ds = new DeflateStream(ms, CompressionLevel.Optimal, true)) ds.Write(data, 0, data.Length);
                    comp = ms.ToArray();
                }
                if (comp.Length >= data.Length) { comp = data; actual = 0; }

                byte[] payload, extra; ushort method, verNeeded; uint crcField;
                if (aes)
                {
                    byte[] salt = new byte[16]; RandomNumberGenerator.Fill(salt);
                    byte[] ek, ak, pwv; AesKeys(password, salt, 32, out ek, out ak, out pwv);
                    byte[] ct = AesCtr(ek, comp);
                    byte[] mac = Mac(ak, ct);
                    payload = new byte[16 + 2 + ct.Length + 10];
                    Buffer.BlockCopy(salt, 0, payload, 0, 16); Buffer.BlockCopy(pwv, 0, payload, 16, 2);
                    Buffer.BlockCopy(ct, 0, payload, 18, ct.Length); Buffer.BlockCopy(mac, 0, payload, 18 + ct.Length, 10);
                    method = 99; verNeeded = 51; crcField = 0;                    // AE-2: no CRC
                    extra = new byte[] { 0x01, 0x99, 0x07, 0x00, 0x02, 0x00, 0x41, 0x45, 0x03, (byte)(actual & 0xFF), (byte)(actual >> 8) };
                }
                else
                {
                    payload = ZcEncrypt(comp, password, crc);
                    method = actual; verNeeded = 20; crcField = crc; extra = new byte[0];
                }
                ushort flags = 0x0801;                                          // encrypted + UTF-8 names
                long offset = fs.Position;

                U32(fs, 0x04034b50u); U16(fs, verNeeded); U16(fs, flags); U16(fs, method); U16(fs, dt); U16(fs, dd);
                U32(fs, crcField); U32(fs, (uint)payload.Length); U32(fs, (uint)data.Length);
                U16(fs, nameBytes.Length); U16(fs, extra.Length);
                fs.Write(nameBytes, 0, nameBytes.Length); fs.Write(extra, 0, extra.Length); fs.Write(payload, 0, payload.Length);

                using (var c = new MemoryStream())
                {
                    U32(c, 0x02014b50u); U16(c, 63); U16(c, verNeeded); U16(c, flags); U16(c, method); U16(c, dt); U16(c, dd);
                    U32(c, crcField); U32(c, (uint)payload.Length); U32(c, (uint)data.Length);
                    U16(c, nameBytes.Length); U16(c, extra.Length); U16(c, 0); U16(c, 0); U16(c, 0); U32(c, 0x20u); U32(c, (uint)offset);
                    c.Write(nameBytes, 0, nameBytes.Length); c.Write(extra, 0, extra.Length);
                    central.Add(c.ToArray());
                }
            }
            long cdStart = fs.Position;
            foreach (var b in central) fs.Write(b, 0, b.Length);
            long cdSize = fs.Position - cdStart;
            U32(fs, 0x06054b50u); U16(fs, 0); U16(fs, 0); U16(fs, central.Count); U16(fs, central.Count);
            U32(fs, (uint)cdSize); U32(fs, (uint)cdStart); U16(fs, 0);
        }
    }

    // ---------------------------------------------------------------- Read
    private sealed class Entry
    {
        public string Name; public ushort Flags, Method, Actual, DosT, DosD; public bool Aes; public int Version, Strength;
        public uint Crc; public long CSize, USize, Offset;
    }

    private static List<Entry> ReadDirectory(byte[] a)
    {
        long eocd = -1;
        for (long i = a.Length - 22; i >= Math.Max(0, a.Length - 22 - 65535); i--) { if (R32(a, i) == 0x06054b50u) { eocd = i; break; } }
        if (eocd < 0) throw new InvalidDataException("Not a zip archive (no end-of-directory record)");
        int count = R16(a, eocd + 10); long cdOff = R32(a, eocd + 16);
        if (cdOff == 0xFFFFFFFFu || count == 0xFFFF) throw new NotSupportedException("Zip64 archives are not supported");
        var list = new List<Entry>();
        long p = cdOff;
        for (int n = 0; n < count; n++)
        {
            if (R32(a, p) != 0x02014b50u) throw new InvalidDataException("Damaged central directory");
            var e = new Entry();
            e.Flags = R16(a, p + 8); e.Method = R16(a, p + 10); e.DosT = R16(a, p + 12); e.DosD = R16(a, p + 14);
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

    public static string[] ListNames(string archivePath)
    {
        byte[] a = File.ReadAllBytes(archivePath);
        var r = new List<string>();
        foreach (var e in ReadDirectory(a)) if (!e.Name.EndsWith("/")) r.Add(e.Name);
        return r.ToArray();
    }

    public static string Describe(string archivePath)
    {
        byte[] a = File.ReadAllBytes(archivePath);
        var l = ReadDirectory(a);
        if (l.Count == 0) return "empty";
        var e = l[0];
        if (e.Aes) return "AES-" + (e.Strength == 3 ? "256" : e.Strength == 2 ? "192" : "128");
        return (e.Flags & 1) != 0 ? "ZipCrypto" : "not encrypted";
    }

    private static byte[] Inflate(byte[] comp, long usize)
    {
        using (var src = new MemoryStream(comp))
        using (var ds = new DeflateStream(src, CompressionMode.Decompress))
        using (var dst = new MemoryStream())
        {
            ds.CopyTo(dst);
            if (dst.Length != usize) throw new InvalidDataException("Size mismatch after decompression");
            return dst.ToArray();
        }
    }

    private static byte[] ReadEntry(byte[] a, Entry e, string password)
    {
        long o = e.Offset;
        if (R32(a, o) != 0x04034b50u) throw new InvalidDataException("Damaged local header of " + e.Name);
        long start = o + 30 + R16(a, o + 26) + R16(a, o + 28);
        byte[] raw = new byte[e.CSize];
        Buffer.BlockCopy(a, (int)start, raw, 0, (int)e.CSize);
        byte[] comp;
        bool checkCrc = true;
        if ((e.Flags & 1) == 0 && !e.Aes) { comp = raw; }
        else if (e.Aes)
        {
            int keyLen = e.Strength == 3 ? 32 : e.Strength == 2 ? 24 : 16, saltLen = keyLen / 2;
            if (raw.Length < saltLen + 2 + 10) throw new InvalidDataException("Damaged AES entry " + e.Name);
            byte[] salt = new byte[saltLen]; Buffer.BlockCopy(raw, 0, salt, 0, saltLen);
            byte[] ek, ak, pwv; AesKeys(password, salt, keyLen, out ek, out ak, out pwv);
            if (raw[saltLen] != pwv[0] || raw[saltLen + 1] != pwv[1]) throw new UnauthorizedAccessException("WRONG_PASSWORD");
            int clen = raw.Length - saltLen - 2 - 10;
            byte[] ct = new byte[clen]; Buffer.BlockCopy(raw, saltLen + 2, ct, 0, clen);
            byte[] mac = new byte[10]; Buffer.BlockCopy(raw, saltLen + 2 + clen, mac, 0, 10);
            if (!CryptographicOperations.FixedTimeEquals(mac, Mac(ak, ct))) throw new InvalidDataException("AUTHENTICATION_FAILED: " + e.Name + " is damaged or was changed");
            comp = AesCtr(ek, ct);
            if (e.Version == 2) checkCrc = false;
        }
        else
        {
            if (raw.Length < 12) throw new InvalidDataException("Damaged ZipCrypto entry " + e.Name);
            var k = new ZcKeys(password);
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
        byte[] data = (e.Actual == 8) ? Inflate(comp, e.USize) : comp;
        if (e.Actual != 0 && e.Actual != 8) throw new NotSupportedException("Compression method " + e.Actual + " of " + e.Name);
        if (data.Length != e.USize) throw new InvalidDataException("Size mismatch of " + e.Name);
        if (checkCrc && Crc32(data) != e.Crc) throw new UnauthorizedAccessException("WRONG_PASSWORD (or damaged data) in " + e.Name);
        return data;
    }

    private static string SafePath(string dest, string name)
    {
        string rel = name.Replace('\\', '/').TrimStart('/');
        if (rel.Length == 0 || rel.IndexOf(':') >= 0) throw new InvalidDataException("Unsafe entry name: " + name);
        foreach (string seg in rel.Split('/')) if (seg == "..") throw new InvalidDataException("Unsafe entry name (..): " + name);
        string root = Path.GetFullPath(dest);
        string full = Path.GetFullPath(Path.Combine(root, rel.Replace('/', Path.DirectorySeparatorChar)));
        if (!full.StartsWith(root.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.Ordinal))
            throw new InvalidDataException("Unsafe entry name (outside the destination): " + name);
        return full;
    }

    // destDir == null: only test (decrypt + authenticate every entry). Returns the entry names.
    public static string[] Extract(string archivePath, string destDir, string password, string[] prefixes)
    {
        byte[] a = File.ReadAllBytes(archivePath);
        var done = new List<string>();
        foreach (var e in ReadDirectory(a))
        {
            if (e.Name.EndsWith("/")) continue;
            if (prefixes != null && prefixes.Length > 0)
            {
                bool hit = false;
                foreach (string p in prefixes) { if (e.Name.Replace('\\', '/').StartsWith(p, StringComparison.OrdinalIgnoreCase)) { hit = true; break; } }
                if (!hit) continue;
            }
            byte[] data = ReadEntry(a, e, password);
            if (!string.IsNullOrEmpty(destDir))        // PowerShell passes $null as ""
            {
                string full = SafePath(destDir, e.Name);
                Directory.CreateDirectory(Path.GetDirectoryName(full));
                File.WriteAllBytes(full, data);
                File.SetLastWriteTime(full, FromDos(e.DosT, e.DosD));
            }
            done.Add(e.Name);
        }
        return done.ToArray();
    }

    public static string Detect(string path)
    {
        byte[] h = new byte[6];
        using (var f = new FileStream(path, FileMode.Open, FileAccess.Read)) { int n = f.Read(h, 0, 6); if (n < 4) return "unknown"; }
        if (h[0] == 0x50 && h[1] == 0x4B && (h[2] == 3 || h[2] == 5)) return "zip";
        if (h[0] == 0x37 && h[1] == 0x7A && h[2] == 0xBC && h[3] == 0xAF && h[4] == 0x27 && h[5] == 0x1C) return "7z";
        return "unknown";
    }
}
'@

function Initialize-PkiZipLibrary {
    if (-not ('PkiZip' -as [type])) { Add-Type -TypeDefinition $script:PkiZipSource -Language CSharp }
}

function Get-PkiArchiveType {
    # "zip" | "7z" | "unknown", from the first bytes of the file (the extension .certpacked says nothing).
    param([Parameter(Mandatory)][string]$Path)
    Initialize-PkiZipLibrary
    return [PkiZip]::Detect($Path)
}

function New-PkiAesZipArchive {
    <#
    .PARAMETER Files
        A list of @{ Source = <file on disk>; Entry = <name inside the archive> }
    .PARAMETER Encryption
        Aes256 (default) | ZipCrypto
    #>
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)]$Files, [Parameter(Mandatory)][string]$Password, [ValidateSet('Aes256', 'ZipCrypto')][string]$Encryption = 'Aes256')
    Initialize-PkiZipLibrary
    $src = [string[]]@($Files | ForEach-Object { $_.Source })
    $ent = [string[]]@($Files | ForEach-Object { $_.Entry })
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    [PkiZip]::Create($Path, $src, $ent, $Password, $Encryption)
}

function Expand-PkiAesZipArchive {
    # Extracts (or, with no -Destination, only tests) a zip: AES-128/192/256 or ZipCrypto. Entry prefixes filter.
    # Wrong password: the message starts with WRONG_PASSWORD.
    param([Parameter(Mandatory)][string]$Path, [string]$Destination, [Parameter(Mandatory)][string]$Password, [string[]]$Prefix)
    Initialize-PkiZipLibrary
    $dest = if ([string]::IsNullOrWhiteSpace($Destination)) { $null } else { $Destination }
    try { return [string[]][PkiZip]::Extract($Path, $dest, $Password, [string[]]@($Prefix)) }
    catch {
        $m = $_.Exception.GetBaseException().Message
        if ($m -like 'WRONG_PASSWORD*') { throw 'WRONG_PASSWORD: the password is wrong (or the file is damaged).' }
        throw $m
    }
}

function Get-PkiAesZipEntries {
    param([Parameter(Mandatory)][string]$Path)
    Initialize-PkiZipLibrary
    return [string[]][PkiZip]::ListNames($Path)
}

# ------------------------------------------------------------
# 7-Zip
# ------------------------------------------------------------
function Find-PkiSevenZip {
    # The 7-Zip command line program, or $null. -Explicit wins.
    param([string]$Explicit)
    if ($Explicit) { if (Test-Path -LiteralPath $Explicit -PathType Leaf) { return (Resolve-Path -LiteralPath $Explicit).Path } else { return $null } }
    $cands = [System.Collections.Generic.List[string]]::new()
    if ($IsWindows) {
        foreach ($d in $env:ProgramFiles, ${env:ProgramFiles(x86)}) { if ($d) { [void]$cands.Add((Join-Path $d '7-Zip\7z.exe')) } }
    }
    foreach ($n in '7zz', '7z', '7za', '7zr', '7z.exe') {
        foreach ($cmd in @(Get-Command $n -All -CommandType Application -ErrorAction SilentlyContinue)) { [void]$cands.Add($cmd.Source) }
    }
    foreach ($c in $cands) { if ($c -and (Test-Path -LiteralPath $c -PathType Leaf)) { return (Resolve-Path -LiteralPath $c).Path } }
    return $null
}

function Invoke-PkiSevenZip {
    # Runs 7-Zip and captures its output. The password is given as  -p<password>  (7-Zip reads it from standard input
    # only when it creates an archive, so an argument is the only way that works in both directions). It is visible in a
    # process list while 7-Zip runs. The default zip format uses the built-in engine and has no such exposure.
    param([Parameter(Mandatory)][string]$Exe, [Parameter(Mandatory)][string[]]$Arguments, [string]$WorkingDirectory)
    $psi = [System.Diagnostics.ProcessStartInfo]::new()
    $psi.FileName = $Exe
    foreach ($a in $Arguments) { [void]$psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true; $psi.RedirectStandardError = $true; $psi.RedirectStandardInput = $true
    $psi.CreateNoWindow = $true
    if ($WorkingDirectory) { $psi.WorkingDirectory = $WorkingDirectory }
    $p = [System.Diagnostics.Process]::Start($psi)
    $p.StandardInput.Close()                      # never wait for a prompt
    $outTask = $p.StandardOutput.ReadToEndAsync(); $errTask = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit()
    return [ordered]@{ ExitCode = $p.ExitCode; StdOut = $outTask.Result; StdErr = $errTask.Result }
}

function New-PkiSevenZipArchive {
    # 7z with AES-256 and ENCRYPTED HEADERS (-mhe=on): the file names are hidden too.
    param([Parameter(Mandatory)][string]$Path, [Parameter(Mandatory)][string]$StagingDirectory, [Parameter(Mandatory)][string]$Password, [string]$Exe)
    $x = Find-PkiSevenZip -Explicit $Exe
    if (-not $x) { throw "7-Zip was not found. A 7z package needs it (Windows: winget install 7zip.7zip; Linux: p7zip / 7zip; macOS: brew install sevenzip) or give -SevenZipPath. The default zip format needs no 7-Zip." }
    if (Test-Path -LiteralPath $Path) { Remove-Item -LiteralPath $Path -Force }
    $r = Invoke-PkiSevenZip -Exe $x -Arguments @('a', '-t7z', '-mhe=on', '-mx=9', "-p$Password", '-bd', '-y', $Path, '*') -WorkingDirectory $StagingDirectory
    if ($r.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $Path)) { throw "7-Zip failed (exit $($r.ExitCode)): $(($r.StdErr + $r.StdOut).Trim() -split "`n" | Select-Object -Last 3)" }
}

function Expand-PkiSevenZipArchive {
    param([Parameter(Mandatory)][string]$Path, [string]$Destination = '', [Parameter(Mandatory)][string]$Password, [string]$Exe, [switch]$TestOnly)
    $x = Find-PkiSevenZip -Explicit $Exe
    if (-not $x) { throw "7-Zip was not found. This package is a 7z archive. Install 7-Zip (Windows: winget install 7zip.7zip; Linux: p7zip / 7zip; macOS: brew install sevenzip) or give -SevenZipPath." }
    if ($TestOnly) { $r = Invoke-PkiSevenZip -Exe $x -Arguments @('t', "-p$Password", '-bd', '-y', $Path) }
    else {
        Ensure-PkiDirectory -Path $Destination
        $r = Invoke-PkiSevenZip -Exe $x -Arguments @('x', "-p$Password", '-bd', '-y', "-o$Destination", $Path)
    }
    if ($r.ExitCode -ne 0) {
        $t = ($r.StdErr + $r.StdOut)
        if ($t -match 'Wrong password|Can not open encrypted archive|ERROR: Data Error in encrypted|Cannot open encrypted') { throw 'WRONG_PASSWORD: the password is wrong (or the file is damaged).' }
        throw "7-Zip failed (exit $($r.ExitCode)): $(($t.Trim() -split "`n" | Select-Object -Last 3) -join ' | ')"
    }
}

function Expand-PkiArchive {
    # Any .certpacked: finds out whether it is zip or 7z and extracts it (or tests it when -Destination is empty).
    param([Parameter(Mandatory)][string]$Path, [string]$Destination, [Parameter(Mandatory)][string]$Password, [string]$SevenZipPath, [string[]]$Prefix)
    $type = Get-PkiArchiveType -Path $Path
    switch ($type) {
        'zip' { return (Expand-PkiAesZipArchive -Path $Path -Destination $Destination -Password $Password -Prefix $Prefix) }
        '7z' {
            if ([string]::IsNullOrWhiteSpace($Destination)) { Expand-PkiSevenZipArchive -Path $Path -Destination '' -Password $Password -Exe $SevenZipPath -TestOnly; return @() }
            Expand-PkiSevenZipArchive -Path $Path -Destination $Destination -Password $Password -Exe $SevenZipPath
            return @(Get-ChildItem -LiteralPath $Destination -Recurse -File | ForEach-Object { $_.FullName.Substring($Destination.Length).TrimStart('\', '/') })
        }
        default { throw "$Path is not a zip or 7z archive (first bytes not recognised): it is not a .certpacked file, or it is damaged." }
    }
}


# ------------------------------------------------------------
# Installing what is missing (7-Zip): the bootstrap scripts do the work
# ------------------------------------------------------------
function Find-PkiCompanionScript {
    # Install-DevEnvironment.ps1 / .sh: next to the running script, in its parent, or next to the modules.
    param([Parameter(Mandatory)][string]$Name)
    $roots = [System.Collections.Generic.List[string]]::new()
    foreach ($r in @($(if ($null -ne $script:Pki -and $script:Pki.Contains('ScriptRoot')) { $script:Pki.ScriptRoot }), $PSScriptRoot, (Split-Path -Parent $PSScriptRoot))) {
        if ($r) { [void]$roots.Add($r); [void]$roots.Add((Split-Path -Parent $r)) }
    }
    foreach ($r in $roots) { if ($r) { $p = Join-Path $r $Name; if (Test-Path -LiteralPath $p -PathType Leaf) { return (Resolve-Path -LiteralPath $p).Path } } }
    return $null
}

function Install-PkiSevenZip {
    # Windows: Install-DevEnvironment.ps1 -Only 7Zip, else WinGet directly. Linux / macOS: Install-DevEnvironment.sh --only 7zip.
    # Returns $true when 7-Zip can be found afterwards.
    if ($IsWindows) {
        $ide = Find-PkiCompanionScript -Name 'Install-DevEnvironment.ps1'
        $pwsh = (Get-Process -Id $PID).Path
        if ($ide) {
            Write-PkiLog "Installing 7-Zip with $ide" 'INFO'
            & $pwsh -NoProfile -ExecutionPolicy Bypass -File $ide -Only 7Zip | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        }
        elseif (Get-Command winget.exe -ErrorAction SilentlyContinue) {
            Write-PkiLog 'Installing 7-Zip with WinGet (7zip.7zip)' 'INFO'
            & winget.exe install --id 7zip.7zip --exact --source winget --accept-source-agreements --accept-package-agreements --silent --disable-interactivity | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
        }
        else { Write-PkiLog 'Neither Install-DevEnvironment.ps1 nor WinGet is available: install 7-Zip by hand (https://www.7-zip.org).' 'WARN'; return $false }
    }
    else {
        $sh = Find-PkiCompanionScript -Name 'Install-DevEnvironment.sh'
        if (-not $sh) { Write-PkiLog 'Install-DevEnvironment.sh was not found next to the scripts: install 7-Zip with your package manager (7zip or p7zip).' 'WARN'; return $false }
        Write-PkiLog "Installing 7-Zip with $sh" 'INFO'
        & bash $sh --yes --only 7zip | ForEach-Object { Write-Host "    $_" -ForegroundColor DarkGray }
    }
    return [bool](Find-PkiSevenZip)
}
