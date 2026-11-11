Agantra PKI proxy - tiny local DNS (steps 1 and 2)
Author: Nicko Satria Utama, Agantra Inovatif OU, nicko@nextmantra.com

WHAT IS NEW
  --mode proxy   (default) proxy only, exactly as before. The names must resolve by hosts file or real DNS.
  --mode full    proxy + tiny local DNS. The DNS listens on loopback only (default 127.0.0.2:53), answers the names listed in
                 appsettings.json and forwards every other name, unchanged, to the DNS servers the OS uses now.
  --clean [--dry-run] | --dns-os-status | --no-os-routing    see OS ROUTING below
  --dns-test     PASS / FAIL / SKIP per name: proxy, tiny DNS, OS lookup, node, java, go (.NET = the OS lookup).
  --env-report   read-only report (OS, WSL, DNS setup, VPN adapters, ports, hosts file, runtimes). Saved as env-report-*.txt.
  --mode on the command line wins over "Mode" in appsettings.json. --config <file> selects another settings file.

OS ROUTING (step 2): how the OS learns about the tiny DNS, and how to remove it
  Programs ask the OS for a name, so the OS must know which names go to the tiny DNS. With --mode full and Administrator/root
  the proxy does this itself, for exactly the listed names, and undoes it:
    Windows : one name-resolution (NRPT) rule per name, comment "AgantraPkiProxy". No wildcard, hosts file untouched.
              Uses powershell.exe with fixed text (Add-/Remove-DnsClientNrptRule). Needs Dns:Bind port 53.
    Linux   : systemd-resolved. systemd-resolved refuses DNS settings on the loopback link and ignores a link without an
              address, so the proxy creates ONE helper link "pkiproxy0" (a dummy network interface, address 192.0.2.53, a
              range reserved for documentation, never routed), lets the tiny DNS answer on that address too, and gives
              resolved the routing domains ~name for that link (never the default route). Held in memory, nothing written
              to /etc. Needs the ip command (iproute2) and the kernel dummy module. Removal = resolvectl revert + ip link del.
              Without systemd-resolved, ip or the dummy module nothing is changed and the fallback is printed.
  After applying, the proxy resolves one name through the OS, preferring a name that is NOT in the hosts file (a name that
  is would answer from the hosts file and prove nothing; on Linux resolvectl is asked without the hosts file and cache).
  --dns-test marks every OS answer as "answered by the hosts file" or "not in the hosts file: answered through DNS". If that does not give the expected address everything is
  removed again at once and the reason is printed.
  Everything applied is recorded in proxy-changes.json (Windows: C:\ProgramData\pkiproxy, Linux: /var/lib/pkiproxy).
  Removal: normal stop (Ctrl+C / --stop / service stop) | next start after a crash | --clean [--dry-run].
  --dns-os-status shows what is applied. --no-os-routing runs the tiny DNS without touching the OS.
  Not elevated: the proxy and DNS still run, the OS is not changed, and it tells you to run elevated or use --hosts-add.
  Domain-joined PCs: group-policy NRPT rules make Windows ignore local rules; the check fails, the rules are removed and
  the administrator must add the names to the policy (see the security hand-over text, coming in step 3).
  As a service: --install-service / --install-systemd with --with-dns (or --mode full, or Mode "full" in the installed settings).
    A plain-proxy service keeps its limited account. A full-mode service runs as LocalSystem (Windows) / root (Linux), because
    adding name-resolution rules or a helper link needs those rights. The Linux unit is the one tested on Ubuntu 26.04:
    root, NoNewPrivileges, ProtectSystem=full, ProtectHome, PrivateTmp, After=systemd-resolved. A stop removes the routing; a crash
    leaves it until the next start (which removes it first) or --clean; --uninstall-* removes anything left.
  Not covered yet: Oracle Linux / CentOS Stream without systemd-resolved and WSL without systemd (send --env-report).

SETTINGS (PkiProxySettings)
  "Mode": "proxy" | "full"
  "Dns": {
    "Bind":   "127.0.0.2:53"   loopback only; anything else is refused
    "Answer": "127.0.0.1"      optional; address returned for the names (default: address of the first http-reverse listener)
    "Ttl":    60               seconds
    "FromRoutes": true         also answer for every host listed under Routes
    "Names": { "crt.nextmantra.internal": "", ... }   one name per line, no wildcards; "" = the Answer address
    "Upstream": []             empty = the DNS servers the OS uses (read again every 20 s, so VPN changes are followed)
  }
  A name that has an address here but no entry under Routes is answered by the proxy with 404 until you add a route.

WHAT TO RUN FIRST
  1. agantra-inovatif-crl-ocsp-proxy-<os> --env-report        (on each machine; send me the text file)
  2. (elevated) agantra-inovatif-crl-ocsp-proxy-<os> --mode full      leave it running
  3. in another prompt:  agantra-inovatif-crl-ocsp-proxy-<os> --dns-test
  Port 53 needs Administrator / root. On Windows, Internet Connection Sharing or Hyper-V/WSL may own port 53 on 0.0.0.0;
  --env-report shows whether 127.0.0.2:53 is free.

NODE.JS NOTE
  dns.lookup(), http, https and fetch use the OS. dns.resolve*() has its own DNS client and ignores OS rules and hosts file.

BUILD
  .\build-me.ps1 [-Rid win-x64] [-Smoke] [-Sums]     needs .NET SDK 10; all *.cs files in this folder are compiled.

SECURITY HAND-OVER (step 3)
  --security-info [--out file]    per-machine text for the administrator: hash, signer, ports, changes, child programs, files,
                                  what to allow in Defender / Bitdefender / ESET / EDR, how to remove everything. Read-only.
  --admin-script [--out-dir dir]  also writes Allow-AgantraPkiProxy.ps1 and Remove-AgantraPkiProxyAllow.ps1 (Windows, Defender).
                                  The scripts check the SHA-256 first and add ONE file exclusion. The proxy never runs them.
  SECURITY-HANDOVER.txt           the note to send with the release.
  An unknown switch now stops the program (nothing starts), so a typo cannot start the server by accident.
  Release flow: .\build-me.ps1 -Sums  ->  sign the binaries  ->  .\build-me.ps1 -SumsOnly  ->  send binary + SHA256SUMS-proxy.txt
  + SECURITY-HANDOVER.txt. Sign with a public code-signing certificate: a certificate from your own PKI is not trusted on
  the customer's machines. Send each release to the vendors as a false-positive report before the customer receives it.
  Audit: python3 tools/audit_scripts.py now scans the .cs files. Findings that are meant carry "audit:allow(rule) reason" in the
  source and are listed with their reason in the [allowed] section.
