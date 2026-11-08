/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

// Signs one OCSP response per issued certificate (index.txt of every CA) with that CA's OCSP responder key and writes
// netlify/data/ocsp-bundle.json. Run it on the machine that holds the PKI, then deploy. Needs OpenSSL 3.x on the PATH.
//
//   node tools/build-bundle.mjs [--pki <dir>[,<dir>...]] [--ca q1-ev,q1-ov] [--days 14] [--include-quantum]
//                               [--openssl <exe>] [--passin-env <VAR>] [--no-verify] [--out <file>]
//
// --pki           PKI folders (default: every ../pki/pki-default-NN)
// --days          how long the signed answers stay valid (default 14); run the script again before they run out
// --passin-env    name of an environment variable that holds the pass phrase of the responder keys, if they are encrypted

import { execFileSync, spawnSync } from "node:child_process";
import { X509Certificate } from "node:crypto";
import { existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import { requestKey, responseStatus } from "../netlify/lib/ocsp.mjs";

const here = dirname(fileURLToPath(import.meta.url));
const project = resolve(here, "..");

function parseArgs(argv) {
  const o = { pki: null, ca: null, days: 14, quantum: false, openssl: "openssl", passinEnv: null, verify: true, out: join(project, "netlify", "data", "ocsp-bundle.json") };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    const next = () => argv[++i] ?? (() => { throw new Error(a + " needs a value"); })();
    if (a === "--pki") o.pki = next().split(",");
    else if (a === "--ca") o.ca = next().split(",");
    else if (a === "--days") o.days = Number(next());
    else if (a === "--include-quantum") o.quantum = true;
    else if (a === "--openssl") o.openssl = next();
    else if (a === "--passin-env") o.passinEnv = next();
    else if (a === "--no-verify") o.verify = false;
    else if (a === "--out") o.out = resolve(next());
    else throw new Error("Unknown switch " + a);
  }
  if (!(o.days >= 1 && o.days <= 365)) throw new Error("--days must be 1..365");
  return o;
}

// Issuing CAs (dv/ov/ev) of one PKI folder that have an index.txt and an OCSP responder certificate + key.
export function discover(pkiDirs, { ca = null, quantum = false } = {}) {
  const found = [], skipped = [];
  for (const pki of pkiDirs) {
    for (const track of quantum ? ["classical", "quantum"] : ["classical"]) {
      const tdir = join(pki, track);
      if (!existsSync(tdir)) continue;
      for (const q of readdirSync(tdir).filter((n) => /^q\d+$/.test(n))) {
        for (const lvl of ["dv", "ov", "ev"]) {
          const name = `${q}-${lvl}`;
          if (ca && !ca.includes(name)) continue;
          const dir = join(tdir, q, lvl);
          const f = {
            pki, name, dir,
            cert: join(dir, `${name}.crt`),
            chain: join(dir, `${name}-chain.crt`),
            index: join(dir, "index.txt"),
            rcert: join(pki, "ocsp", name, `${name}-ocsp.crt`),
            rkey: join(pki, "ocsp", name, `${name}-ocsp.key`),
            root: join(pki, "root", "root.crt"),
          };
          const missing = ["cert", "chain", "index", "rcert", "rkey", "root"].filter((k) => !existsSync(f[k]));
          if (missing.length) { if (existsSync(dir)) skipped.push(`${pki.split(/[\\/]/).pop()}/${name}: missing ${missing.join(", ")}`); continue; }
          found.push(f);
        }
      }
    }
  }
  return { found, skipped };
}

// index.txt lines: status \t expiry \t revocation \t serial \t file \t subject
export function readIndex(path) {
  const rows = [];
  for (const line of readFileSync(path, "utf8").split(/\r?\n/)) {
    const f = line.split("\t");
    if (f.length < 4 || !/^[VRE]$/.test(f[0])) continue;
    rows.push({ status: f[0], serial: f[3].trim().toUpperCase() });
  }
  return rows;
}

function main() {
  const o = parseArgs(process.argv.slice(2));
  const pkiRoot = resolve(project, "..", "pki");
  const pkis = (o.pki ?? readdirSync(pkiRoot).filter((n) => /^pki-default-\d+$/.test(n)).map((n) => join(pkiRoot, n))).map((p) => resolve(p));
  const { found, skipped } = discover(pkis, { ca: o.ca, quantum: o.quantum });
  if (found.length === 0) throw new Error("No CA with index.txt + OCSP responder found in: " + pkis.join(", "));
  for (const s of skipped) console.log("  skip  " + s);

  const startMs = Date.now();
  let validUntil = Math.floor(startMs / 1000) + o.days * 86400 - 60;
  const tmp = mkdtempSync(join(tmpdir(), "ocspbundle-"));
  const entries = {};
  const passin = o.passinEnv ? ["-passin", "env:" + o.passinEnv] : [];
  const run = (args) => execFileSync(o.openssl, args, { stdio: ["ignore", "pipe", "pipe"], encoding: "utf8" });
  const failures = [];

  try {
    for (const ca of found) {
      const label = `${ca.pki.split(/[\\/]/).pop()}/${ca.name}`;
      const rc = new X509Certificate(readFileSync(ca.rcert));
      const cc = new X509Certificate(readFileSync(ca.cert));
      const stop = Math.min(Date.parse(rc.validTo), Date.parse(cc.validTo)) / 1000;
      if (stop < validUntil) {
        console.log(`  warn  ${label}: responder/CA certificate ends ${new Date(stop * 1000).toISOString().slice(0, 10)}, answers end then`);
        validUntil = Math.floor(stop) - 60;
      }
      const trust = join(tmp, "trust.pem");
      writeFileSync(trust, readFileSync(ca.chain, "utf8") + "\n" + readFileSync(ca.root, "utf8"));

      const rows = readIndex(ca.index).filter((r) => r.status !== "E");
      let n = 0;
      for (const row of rows) {
        for (const digest of ["sha1", "sha256"]) {
          const req = join(tmp, "req.der"), resp = join(tmp, "resp.der");
          try {
            run(["ocsp", "-issuer", ca.cert, "-" + digest, "-serial", "0x" + row.serial, "-no_nonce", "-reqout", req]);
            run(["ocsp", "-index", ca.index, "-CA", ca.cert, "-rsigner", ca.rcert, "-rkey", ca.rkey, ...passin,
              "-reqin", req, "-respout", resp, "-ndays", String(o.days), "-nrequest", "1"]);
            const der = readFileSync(resp);
            const st = responseStatus(der);
            if (st !== 0) throw new Error("responder answered with status " + st);
            if (o.verify) {
              const v = spawnSync(o.openssl, ["ocsp", "-respin", resp, "-issuer", ca.cert, "-" + digest, "-serial", "0x" + row.serial, "-CAfile", trust], { encoding: "utf8" }); // OpenSSL reports on stderr
              const out = (v.stdout ?? "") + (v.stderr ?? "");
              const want = row.status === "R" ? "revoked" : "good";
              if (!/Response verify OK/.test(out) || !new RegExp(":\\s*" + want + "\\b").test(out)) throw new Error("verification failed: " + out.trim().split("\n").slice(0, 3).join(" | "));
            }
            entries[requestKey(readFileSync(req))] = der.toString("base64");
            n++;
          } catch (e) {
            failures.push(`${label} serial ${row.serial} (${digest}): ${(e.stderr || e.message || e).toString().trim().split("\n")[0]}`);
          }
        }
      }
      console.log(`  ok    ${label}: ${rows.length} certificate(s), ${n} answer(s)`);
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }

  if (failures.length) { for (const f of failures.slice(0, 10)) console.error("  FAIL  " + f); if (failures.length > 10) console.error(`  ... and ${failures.length - 10} more`); throw new Error(failures.length + " answer(s) could not be made; bundle not written"); }

  const keys = Object.keys(entries).sort();
  const lines = keys.map((k) => `    ${JSON.stringify(k)}: ${JSON.stringify(entries[k])}`);
  writeFileSync(o.out, `{\n  "generated": ${JSON.stringify(new Date(startMs).toISOString())},\n  "validUntil": ${validUntil},\n  "validUntilIso": ${JSON.stringify(new Date(validUntil * 1000).toISOString())},\n  "entries": {\n${lines.join(",\n")}\n  }\n}\n`);
  console.log(`\nWrote ${keys.length} answer(s) to ${o.out}\nValid until ${new Date(validUntil * 1000).toISOString()} - run this script again and deploy before then.`);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try { main(); } catch (e) { console.error("ERROR: " + e.message); process.exit(1); }
}
