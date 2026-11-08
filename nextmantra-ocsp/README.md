# nextmantra-ocsp - pre-signed OCSP responder (Netlify)

Author: Nicko Satria Utama - Agantra Inovatif OU - nicko@nextmantra.com

`ocsp.nextmantra.com` answers OCSP requests for the Agantra private PKI. **Nothing is signed online.** On the PKI machine,
`tools/build-bundle.mjs` signs one OCSP response per issued certificate (from each CA's `index.txt`, with that CA's own
OCSP responder key) and stores them in `netlify/data/ocsp-bundle.json`. The Netlify function only looks the right answer up.
No private key ever reaches Netlify, and a request costs one hash-map lookup.

```
client --http--> ocsp.nextmantra.internal --(pki proxy)--> https://ocsp.nextmantra.com --> netlify/functions/ocsp.mjs --> bundle
```

## Update the answers (do this before `validUntil`, default every 14 days; also after every revocation or new certificate)

```powershell
node tools/build-bundle.mjs            # all pki-default-NN folders next to this project, 14 days
node tools/build-bundle.mjs --pki ..\pki\pki-default-04 --days 30
node tools/selftest.mjs                # OpenSSL checks the answers through the real function
# then deploy (see below)
```

Switches: `--pki <dir,dir>`, `--ca q1-ev,q1-ov`, `--days N`, `--include-quantum`, `--openssl <exe>`, `--passin-env <VAR>`
(pass phrase of the responder keys, if they are encrypted), `--no-verify`, `--out <file>`.
Every answer is verified with `openssl ocsp -respin` (signature, chain up to the root, and good/revoked) before the file is written;
if one answer fails nothing is written.

## What the client gets

| Request | Answer |
|---|---|
| certificate in the bundle (SHA-1 or SHA-256 CertID) | the signed `good` / `revoked` answer |
| unknown CA or serial | `unauthorized` (unsigned, HTTP 200) |
| unreadable request | `malformedRequest` |
| bundle older than `validUntil` | `tryLater` (the client falls back to the CRL) |
| `GET /` , other methods, wrong content type | 404 / 405 / 415 |

Requests with a nonce are answered without the nonce (pre-signed answers cannot echo it); Windows does not send one.
CAs without an OCSP responder (the roots) are not covered; clients check those through the CRL.

## Deploy

The function needs a real Netlify deploy (Git integration, or `netlify deploy --prod` with the Netlify CLI from this folder);
a drag-and-drop of the folder does not build functions. `netlify.toml` already points at `netlify/functions`, publishes `public/`,
and the function claims `/*` itself, so no redirect is needed. The old `ocsp-mock.js` (which returned an invalid fixed answer) is gone.

Check after deploying (from a machine that resolves `ocsp.nextmantra.com`):

```powershell
curl.exe -s -o NUL -w "%{http_code} %{content_type}`n" https://ocsp.nextmantra.com/MEEwQDA...   # expects 200 application/ocsp-response
certutil -verify -urlfetch <signed-file-or-certificate>                                         # OCSP and CRL should both say verified
```
