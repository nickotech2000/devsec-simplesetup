/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

// Checks the responder the way a client uses it: builds real OCSP requests with OpenSSL, sends them through the Netlify
// function (GET and POST), and lets OpenSSL verify the answer. Needs OpenSSL on the PATH and the PKI folder next to this project.
//   node tools/selftest.mjs [--pki <dir>] [--ca q1-ev] [--openssl <exe>]

import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import handler from "../netlify/functions/ocsp.mjs";
import { respond, responseStatus, STATUS } from "../netlify/lib/ocsp.mjs";
import { discover, readIndex } from "./build-bundle.mjs";

const project = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const arg = (n, d) => { const i = process.argv.indexOf(n); return i > 0 ? process.argv[i + 1] : d; };
const openssl = arg("--openssl", "openssl");
const pki = resolve(arg("--pki", join(project, "..", "pki", "pki-default-04")));
const caName = arg("--ca", "q1-ev");
const bundle = JSON.parse(readFileSync(join(project, "netlify", "data", "ocsp-bundle.json"), "utf8"));

let failed = 0;
const check = (name, ok, extra = "") => { console.log((ok ? "  ok   " : "  FAIL ") + name + (ok ? "" : " " + extra)); if (!ok) failed++; };

const { found } = discover([pki], { ca: [caName] });
if (!found.length) { console.error("CA not found: " + caName + " in " + pki); process.exit(1); }
const ca = found[0];
const rows = readIndex(ca.index).filter((r) => r.status !== "E");
const tmp = mkdtempSync(join(tmpdir(), "ocspselftest-"));
const trust = join(tmp, "trust.pem");
writeFileSync(trust, readFileSync(ca.chain, "utf8") + "\n" + readFileSync(ca.root, "utf8"));

function makeRequest(serial, digest) {
  const f = join(tmp, `req-${serial}-${digest}.der`);
  const r = spawnSync(openssl, ["ocsp", "-issuer", ca.cert, "-" + digest, "-serial", "0x" + serial, "-no_nonce", "-reqout", f], { encoding: "utf8" });
  if (r.status !== 0) throw new Error("openssl request failed: " + r.stderr);
  return readFileSync(f);
}

function verify(body, serial, digest, want) {
  const f = join(tmp, "resp.der");
  writeFileSync(f, body);
  const v = spawnSync(openssl, ["ocsp", "-respin", f, "-issuer", ca.cert, "-" + digest, "-serial", "0x" + serial, "-CAfile", trust], { encoding: "utf8" });
  const out = (v.stdout ?? "") + (v.stderr ?? "");
  return /Response verify OK/.test(out) && new RegExp(":\\s*" + want + "\\b").test(out);
}

try {
  console.log(`CA ${caName} in ${pki.split(/[\\/]/).pop()}: ${rows.length} certificate(s); bundle has ${Object.keys(bundle.entries).length} answer(s)`);
  for (const row of rows.slice(0, 3)) {
    const want = row.status === "R" ? "revoked" : "good";
    for (const digest of ["sha1", "sha256"]) {
      const der = makeRequest(row.serial, digest);
      const post = respond(bundle, { method: "POST", path: "/", contentType: "application/ocsp-request", body: der });
      check(`POST ${digest} ${row.serial.slice(-6)} -> ${want}`, post.status === 200 && post.headers["Content-Type"] === "application/ocsp-response" && verify(post.body, row.serial, digest, want));
      const b64 = Buffer.from(der).toString("base64");
      const get = respond(bundle, { method: "GET", path: "/" + encodeURIComponent(b64) });
      check(`GET  ${digest} ${row.serial.slice(-6)} (url-encoded) -> ${want}`, get.status === 200 && verify(get.body, row.serial, digest, want));
      const raw = respond(bundle, { method: "GET", path: "/" + b64 });
      check(`GET  ${digest} ${row.serial.slice(-6)} (not encoded) -> ${want}`, raw.status === 200 && verify(raw.body, row.serial, digest, want));
    }
  }

  // The same through the Netlify function wrapper (Web Request/Response)
  const der = makeRequest(rows[0].serial, "sha1");
  const viaPost = await handler(new Request("https://ocsp.nextmantra.com/", { method: "POST", headers: { "content-type": "application/ocsp-request" }, body: der }));
  check("function: POST", viaPost.status === 200 && verify(Buffer.from(await viaPost.arrayBuffer()), rows[0].serial, "sha1", rows[0].status === "R" ? "revoked" : "good"));
  const viaGet = await handler(new Request("https://ocsp.nextmantra.com/" + encodeURIComponent(Buffer.from(der).toString("base64"))));
  check("function: GET", viaGet.status === 200 && viaGet.headers.get("cache-control").startsWith("public"));

  // Error paths
  const unknown = makeRequest("0ABCDEF0123456789", "sha1");
  const u = respond(bundle, { method: "POST", path: "/", contentType: "application/ocsp-request", body: unknown });
  check("unknown serial -> unauthorized", u.status === 200 && responseStatus(u.body) === STATUS.unauthorized);
  const g = respond(bundle, { method: "POST", path: "/", contentType: "application/ocsp-request", body: Buffer.from("not an ocsp request") });
  check("garbage -> malformedRequest", g.status === 200 && responseStatus(g.body) === STATUS.malformed);
  check("wrong content type -> 415", respond(bundle, { method: "POST", path: "/", contentType: "text/plain", body: unknown }).status === 415);
  check("PUT -> 405", respond(bundle, { method: "PUT", path: "/" }).status === 405);
  check("GET / -> 404", respond(bundle, { method: "GET", path: "/" }).status === 404);
  const late = respond(bundle, { method: "POST", path: "/", contentType: "application/ocsp-request", body: der, nowMs: (bundle.validUntil + 10) * 1000 });
  check("after validUntil -> tryLater", late.status === 200 && responseStatus(late.body) === STATUS.tryLater);
} finally {
  rmSync(tmp, { recursive: true, force: true });
}

console.log(failed ? `\n${failed} check(s) FAILED` : "\nAll checks passed");
process.exit(failed ? 1 : 0);
