# Compatibility guide

Browsers, devices and web servers for the EV TLS leaf certificate
(`serverAuth` + `clientAuth`) made by `pki_setup.ps1` and
`GenerateLeafCertificate.ps1`.

**Two things decide whether a device accepts a certificate:**

1. The certificate itself must meet what the TLS stack requires. The leaf is built for that (section 1).
2. The device must **trust your Root CA**. This is a private PKI, so this step is always yours (section 2).

Section 5 lists what was tested and what was not.

---

## 1. What the leaf certificate contains

| Property | Value | Why |
|---|---|---|
| Subject Alternative Name | DNS names (wildcards allowed), IP addresses, e-mail | Chrome, Edge, Brave, Firefox, Safari and Go ignore the CN and use the SAN only |
| Extended Key Usage | `serverAuth`, `clientAuth` | Required by every TLS server stack; `clientAuth` allows mutual TLS |
| Key Usage | RSA: `digitalSignature, keyEncipherment`; ECC: `digitalSignature` | Works with TLS 1.2 RSA key exchange (old clients) and TLS 1.3 |
| Key | RSA 2048 (default) / 3072 / 4096 / 8192, or ECC P-256 / P-384 / P-521 | Above the 2048 / 256-bit floor of Apple, Chrome, Firefox |
| Signature | SHA-256 (default), SHA-384, SHA-512 | SHA-1 is rejected by all current clients |
| Validity | 397 days (maximum 398) | Satisfies Apple's and Chrome's 398-day limit |
| Basic Constraints | `CA:FALSE`, critical | |
| Key identifiers | Subject Key Identifier + Authority Key Identifier | Chain building (Windows, Android, Safari) |
| Serial number | 128-bit random, positive (`GenerateLeafCertificate.ps1`) | Under the 20-octet limit; no duplicate issuer+serial |
| Key file format | PKCS#8 PEM (`-----BEGIN PRIVATE KEY-----`) | Read by OpenSSL, Go, Node, Java, Mongoose |
| Chain file | `<name>-fullchain.crt` = leaf + Intermediate | Servers must send the intermediate |
| CRL / OCSP / CA Issuers | URLs from `ev_pki.cnf` | See section 4 |

The EV policy OID (`2.23.140.1.1`) and the EV subject fields are carried in the certificate. They do not
change how any TLS stack validates it. **No browser shows the EV company line for a private root**
(Chrome / Edge: "Issued to: <company>" is reserved for roots in the browser's built-in EV list).
The company name is visible under *Show certificate*.

**Larger keys:** the Root and Intermediate CA keys are RSA 8192. OpenSSL, Go, Java, Node, Python and
curl verified chains built on them (section 5). Browsers, phones and embedded stacks were not tested
with 8192-bit CA keys; if one refuses the chain, reissue the CAs with a smaller key.

---

## 2. Trust the Root CA on each device

Install **`pki\root\root.crt`** (also `pki\publish\root.crt`). The Intermediate is sent by the server in
the fullchain file, so it does not have to be installed.

### Desktop

| Platform | How |
|---|---|
| **Windows 10 / 11** | `.\pki_setup.ps1 -InstallTrust` or `.\pki_reuse.ps1` (elevated). Chrome, Edge and Brave on Windows use the Windows store. |
| **Windows (manual)** | `certlm.msc` → Trusted Root Certification Authorities → Import `root.crt`. |
| **macOS (Safari, Chrome, Edge, Brave)** | `sudo security add-trusted-cert -d -r trustRoot -k /Library/Keychains/System.keychain root.crt` |
| **Ubuntu (system, curl, Node via system CA)** | `sudo cp root.crt /usr/local/share/ca-certificates/nextmantra-root.crt && sudo update-ca-certificates` |
| **Ubuntu: Chrome / Chromium / Edge / Brave** | They use the NSS database: `sudo apt install libnss3-tools`, then `certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n NextMantraRoot -i root.crt` |
| **Firefox (all desktop OS)** | Own store: Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import (tick *Trust to identify websites*). Or set `security.enterprise_roots.enabled` = `true` in `about:config` to use the OS store. |

### Tablet and phone

| Platform | How |
|---|---|
| **Android (Xiaomi Pad 7S Pro, Xiaomi 15 Ultra, Redmi Note 14 5G, vivo / OriginOS devices)** | Copy `root.crt` to the device → Settings → Security / Passwords & security → *Encryption & credentials* (name varies by ROM) → *Install a certificate* → *CA certificate*. A screen lock is required. |
| **Android apps** | Apps that target Android 7+ ignore user-installed CAs unless their `network_security_config` allows them. Chrome honours the user store. |
| **iOS / iPadOS (Safari)** | Open `root.crt` → Settings → *Profile Downloaded* → Install, then **Settings → General → About → Certificate Trust Settings → enable full trust** for the root. Without the last step Safari still rejects it. |
| **UC Browser, QQ Browser** | Install the CA as above. These browsers use their own engine on some platforms; whether they read the Android user store was not tested. If the page is still rejected, use Chrome / Edge on that device, or the in-app certificate settings of the browser. |

### Emulators

| Target | How |
|---|---|
| **iOS Simulator** | `xcrun simctl keychain booted add-root-cert root.crt` |
| **Android Emulator** | Same steps as a phone (user store). A system-store install needs a writable-system / non-Play image. |
| **Hyper-V Ubuntu** | Same as Ubuntu above. |

Reach the dev machine by a name in the SAN. An emulator reaches the host as `10.0.2.2` (not in the
development SAN set): add it with `-IP4 10.0.2.2`, or map a SAN name such as `local.dev` to the host.

---

## 3. Web servers

Files per certificate: `<name>.crt`, `<name>.key`, `<name>-fullchain.crt`, `<name>.pfx`.
Copy `root.crt` to every client (section 2).

### Apache HTTP Server 2.4.x (tested 2.4.58)
```apache
SSLEngine on
SSLProtocol -all +TLSv1.2 +TLSv1.3
SSLCertificateFile      /etc/pki/nextmantra.com.crt
SSLCertificateKeyFile   /etc/pki/nextmantra.com.key
SSLCertificateChainFile /etc/pki/nextmantra.com-fullchain.crt
# mutual TLS
# SSLCACertificateFile  /etc/pki/ca-bundle.crt     # intermediate + root
# SSLVerifyClient require
# SSLCARevocationFile   /etc/pki/agantra-rsa-ev-ca-g1.crl.pem.crl ; SSLCARevocationCheck leaf
```

### Nginx (tested 1.24)
```nginx
ssl_certificate     /etc/pki/nextmantra.com-fullchain.crt;
ssl_certificate_key /etc/pki/nextmantra.com.key;
ssl_protocols       TLSv1.2 TLSv1.3;
# mutual TLS
# ssl_client_certificate /etc/pki/ca-bundle.crt;   # intermediate + root
# ssl_verify_client on;
# ssl_crl /etc/pki/agantra-rsa-ev-ca-g1.crl.pem.crl;
```

### IIS (Windows 11, Windows Server 2022, Windows Server 2025)
```powershell
Import-PfxCertificate -FilePath .\nextmantra.com.pfx -CertStoreLocation Cert:\LocalMachine\My `
    -Password (Read-Host -AsSecureString)
```
Then IIS Manager → Site → Bindings → https → select the certificate. Install the Root CA on the server
as well (`pki_reuse.ps1`) so client certificates validate. For client certificates set *SSL Settings →
Client certificates → Require*. The default (non-legacy) PFX encryption is supported by these Windows
versions; do not use `-LegacyPfx`.

### Kestrel (.NET 10 / .NET 11)
```csharp
builder.WebHost.ConfigureKestrel(k => k.ConfigureHttpsDefaults(h =>
{
    h.ServerCertificate = X509CertificateLoader.LoadPkcs12FromFile("nextmantra.com.pfx", password);
    // mutual TLS:
    // h.ClientCertificateMode = ClientCertificateMode.RequireCertificate;
    // h.CheckCertificateRevocation = false;   // unless the CRL / OCSP URLs are reachable
}));
```
On Linux Kestrel can also read `CreateFromPemFile("...-fullchain.crt", "....key")`.

### Node.js 24 / 26
```js
https.createServer({
  key:  fs.readFileSync('nextmantra.com.key'),
  cert: fs.readFileSync('nextmantra.com-fullchain.crt'),
  // mutual TLS: requestCert: true, rejectUnauthorized: true, ca: fs.readFileSync('ca-bundle.crt'),
}, handler).listen(443);
// or: { pfx: fs.readFileSync('nextmantra.com.pfx'), passphrase }
```
Client: `https.get(url, { ca: fs.readFileSync('root.crt') })`, or run with `NODE_EXTRA_CA_CERTS=root.crt`.

### PHP 5
Use PEM files, not the PFX. PHP 5.6+ is needed for TLS 1.2.
```php
$ctx = stream_context_create(['ssl' => [
    'cafile' => 'root.crt', 'verify_peer' => true, 'verify_peer_name' => true,
    // client certificate: 'local_cert' => 'nextmantra.com-fullchain.crt', 'local_pk' => 'nextmantra.com.key',
]]);
```
Keep the default RSA key (2048 or 3072) and SHA-256: that is what old OpenSSL 1.0.x builds handle best.
To read a PFX with `openssl_pkcs12_read` on such a build, generate it with `-LegacyPfx`.

### Go 1.27
```go
cert, err := tls.LoadX509KeyPair("nextmantra.com-fullchain.crt", "nextmantra.com.key")
srv := &http.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}}
// client: pool := x509.NewCertPool(); pool.AppendCertsFromPEM(rootPEM); tls.Config{RootCAs: pool}
```

### Mongoose
There are two products with this name.

* **Cesanta Mongoose (embedded C web server).** Its built-in TLS stack was designed for ECC; RSA
  support is newer and depends on the version. For the built-in stack issue an ECC certificate:
  `-Algorithm ECC -Bit 256`. For RSA, build with the OpenSSL or mbedTLS backend (`MG_TLS`).
  Keys are PKCS#8 (`BEGIN PRIVATE KEY`), which it accepts. Mutual TLS: use Mongoose 7.21 or newer if you
  ever use a P-384 CA (this PKI's CAs are RSA).
* **Mongoose (Node.js ODM for MongoDB).** Put the certificate and key in one PEM:
  `cat nextmantra.com.crt nextmantra.com.key > client.pem`, then connect with
  `tls: true, tlsCAFile: 'root.crt', tlsCertificateKeyFile: 'client.pem'`.

---

## 4. CRL, OCSP and CA Issuers

Every leaf carries these locations (from `ev_pki.cnf`):

| Type | Location |
|---|---|
| CRL | `http://crl-01.nextmantra.com/agantra-rsa-ev-ca-g1.crl`, `http://crl-02.nextmantra.com/...`, `http://crl-dev.nextmantra.internal/...` |
| OCSP | `http://ocsp.nextmantra.internal`, `http://ocsp.nextmantra.com` |
| CA Issuers | `http://crt-01.nextmantra.com/agantra-rsa-ev-ca-g1.crt`, `-02`, `crt-dev.nextmantra.internal` |

`pki_setup.ps1` writes the CRL (DER), the CA-issuer certificate (DER) and a PEM CRL to `pki\publish\`.
Copy them to the hosts above. Nothing is served for you.

* **Browsers on a private root** do not hard-fail on an unreachable CRL / OCSP.
* **Windows client-certificate logins** (IIS, Kestrel mutual TLS) do: they report *revocation server
  offline* until one location answers. Serve the files, or turn revocation checking off on that server,
  or generate certificates with `-NoRevocationInfo`.
* The CRL expires after 365 days. Regenerate it before then:
  `openssl ca -gencrl -config pki\openssl.runtime.cnf -out agantra-rsa-ev-ca-g1.crl.pem`
* OCSP: `pki\publish\README.txt` shows an `openssl ocsp` command for a lab responder.

---

## 5. What was tested and what was not

**Tested** (OpenSSL 3.0.13, Ubuntu 24.04): the TLS certificate (RSA 2048 and ECC P-256) served by
**nginx 1.24**, **Apache 2.4.58** and a **Go 1.22** server, with clients **curl, OpenSSL s_client,
Python 3 ssl, Node 22, Go 1.22 and Java 21**, each trusting only the Root CA:

* verified for `nextmantra.com`, a wildcard match (`app.nextmantra.local`, `shop.raksakateknologi.api`),
  `local.dev`, and the IP `127.0.0.1`; a wrong hostname was rejected by every client
* mutual TLS on nginx with the same certificate as the client certificate (curl, OpenSSL, Python, Node, Go);
  a request without a client certificate was refused
* OpenSSL strict (`-x509_strict`) verification for the server and client purposes, and `10.10.2.2` / `::1` in the SAN
* the PFX files open in Node 22 and Java 21; the `-LegacyPfx` file opens with OpenSSL `-legacy`

**Not tested (no way to run them here):** Windows Schannel / IIS / Kestrel on .NET 10 or 11,
Node 24 / 26, Go 1.27, PHP 5, Cesanta Mongoose, Chrome, Edge, Firefox, Safari, Brave, UC Browser and
QQ Browser, and the physical devices (Xiaomi, Redmi, vivo) and simulators. For those, the certificate
was checked against the properties those stacks require (section 1); the installation steps in
sections 2 and 3 follow each platform's documented procedure. Check one page per device after installing
the Root CA.
