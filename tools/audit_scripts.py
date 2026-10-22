#!/usr/bin/env python3
# Author : Nicko Satria Utama   Company: Agantra Inovatif OÜ (NextMantra)   Email: nicko@nextmantra.com   Version: 7.9.1
# Developer tool: static audit of every script for patterns that malware uses. Read only.
# Use:  python3 tools/audit_scripts.py [--sums]    (--sums writes SHA256SUMS of all files except pki/ transport/ ...)
import os, re, sys, hashlib, unicodedata
root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
skip = ('.git', 'pki', 'transport', 'leafcerts', 'csr-signed', 'external-ca', 'backup-pki')
RULES = [  # (id, regex, what it would mean)
 ('encoded-command',   r'(?i)(-enc(odedcommand)?\b|FromBase64String|\[Convert\]::FromBase64|base64\s+-d|certutil\s+-decode)', 'decodes hidden code'),
 ('invoke-expression', r'(?i)(\bInvoke-Expression\b|\biex\b\s*[\(\$"\']|\beval\s+["\$`])', 'runs text as code'),
 ('download-exec',     r'(?i)(DownloadString|DownloadFile|Net\.WebClient|Invoke-WebRequest|Invoke-RestMethod|curl[^|\n]*\|\s*(ba)?sh|wget[^|\n]*\|\s*(ba)?sh|bitsadmin|Start-BitsTransfer)', 'downloads something'),
 ('hidden-window',     r'(?i)(-WindowStyle\s+Hidden|-w\s+hidden|CreateNoWindow\s*=\s*\$true)', 'hides a window'),
 ('exec-policy',       r'(?i)(-ExecutionPolicy\s+Bypass|Set-ExecutionPolicy)', 'switches off script policy'),
 ('persistence',       r'(?i)(CurrentVersion\\Run|schtasks|Register-ScheduledTask|New-Service|sc\.exe\s+create|crontab|/etc/cron|rc\.local|\.bashrc|authorized_keys)', 'starts itself later'),
 ('defender-off',      r'(?i)(Set-MpPreference|Add-MpPreference|DisableRealtimeMonitoring|ExclusionPath|netsh\s+advfirewall|ufw\s+disable)', 'weakens protection'),
 ('credential-theft',  r'(?i)(mimikatz|lsass|sekurlsa|SAM\b.*hive|/etc/shadow|Get-Credential\b.*-Message)', 'steals secrets'),
 ('raw-socket-shell',  r'(?i)(/dev/tcp/|nc\s+-e|ncat\s+-e|bash\s+-i\s*>&|TCPClient|socat\s+.*exec)', 'reverse shell'),
 ('shadow-delete',     r'(?i)(vssadmin|wbadmin\s+delete|bcdedit|cipher\s+/w|wevtutil\s+cl|Clear-EventLog)', 'ransomware / log wipe'),
 ('long-blob',         r'[A-Za-z0-9+/=]{300,}', 'very long encoded string'),
 ('sudo-nopasswd',     r'(?i)NOPASSWD|chmod\s+[0-7]*[46]7[0-7]*\s|chmod\s+u\+s|setuid', 'privilege tricks'),
]
bad_chars = {'‮', '‭', '​', '‌', '‍', '⁠', '﻿'}
files = []
for d, dn, fn in os.walk(root):
    rel = os.path.relpath(d, root)
    if rel.split(os.sep)[0] in skip: dn[:] = []; continue
    for f in fn: files.append(os.path.join(d, f))
files.sort()
code = [f for f in files if f.endswith(('.ps1', '.sh', '.py', '.psm1', '.psd1', '.bat', '.cmd', '.js', '.html'))]
hits = {}; urls = {}; nonasc = []
for f in code:
    rel = os.path.relpath(f, root)
    if rel.startswith('html'): continue
    t = open(f, encoding='utf-8', errors='replace').read()
    if rel == os.path.join('tools', 'audit_scripts.py'): continue
    for i, l in enumerate(t.split('\n'), 1):
        for rid, rx, what in RULES:
            if re.search(rx, l): hits.setdefault(rid, []).append((rel, i, l.strip()[:110]))
        for u in re.findall(r'https?://[A-Za-z0-9._\-]+', l): urls.setdefault(u.lower(), set()).add(rel)
        if any(c in bad_chars for c in l.replace('﻿', '', 1) if i > 1 or c != '﻿'): nonasc.append((rel, i))
print('Files scanned:', len(code))
for rid, rx, what in RULES:
    h = hits.get(rid, [])
    print(f'\n[{rid}] {what}: {len(h)} line(s)')
    for rel, i, l in h[:40]: print(f'   {rel}:{i}: {l}')
print('\n[hidden-unicode] zero-width or bidi characters:', len(nonasc))
for rel, i in nonasc[:20]: print('  ', rel, i)
print('\n[urls] every host named in the scripts:')
for u in sorted(urls): print('  ', u, '  (%d file(s))' % len(urls[u]))
if '--sums' in sys.argv:
    out = []
    for f in files:
        rel = os.path.relpath(f, root).replace(os.sep, '/')
        if rel in ('SHA256SUMS',) or rel.endswith('.zip'): continue
        out.append(hashlib.sha256(open(f, 'rb').read()).hexdigest() + '  ' + rel)
    open(os.path.join(root, 'SHA256SUMS'), 'w', newline='\n').write('\n'.join(out) + '\n')
    print('\nSHA256SUMS written:', len(out), 'files')
