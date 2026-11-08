/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

// Pre-signed OCSP responder (RFC 6960). Nothing is signed here: tools/build-bundle.mjs signs one response per issued
// certificate with the CA's own OCSP responder key (offline), and this code only finds the right response for a request.

const OID_NAMES = {
  "2b0e03021a": "sha1",
  "608648016503040201": "sha256",
  "608648016503040202": "sha384",
  "608648016503040203": "sha512",
};

// OCSPResponseStatus values for the unsigned error answers.
export const STATUS = { malformed: 1, internalError: 2, tryLater: 3, unauthorized: 6 };

export function statusResponse(code) {
  return Uint8Array.of(0x30, 0x03, 0x0a, 0x01, code);
}

// responseStatus of an OCSPResponse (0 = successful), or -1 when it is not one
export function responseStatus(der) {
  try {
    const b = Buffer.from(der);
    const outer = expect(tlv(b, 0), 0x30);
    const st = expect(tlv(b, outer.s), 0x0a);
    return b[st.s];
  } catch {
    return -1;
  }
}

// One DER element at position p: { tag, s: content start, e: content end }
function tlv(b, p) {
  if (p + 2 > b.length) throw new Error("short");
  const tag = b[p];
  let len = b[p + 1];
  let q = p + 2;
  if (len & 0x80) {
    const n = len & 0x7f;
    if (n === 0 || n > 3 || q + n > b.length) throw new Error("bad length");
    len = 0;
    for (let i = 0; i < n; i++) len = len * 256 + b[q++];
  }
  if (q + len > b.length) throw new Error("truncated");
  return { tag, s: q, e: q + len };
}

function expect(t, tag) {
  if (t.tag !== tag) throw new Error("unexpected tag");
  return t;
}

const hex = (b, s, e) => Buffer.from(b.subarray(s, e)).toString("hex");

// Returns the lookup key of the first CertID of an OCSPRequest: "<hash>:<nameHash>:<keyHash>:<serial>".
// The serial is normalised (no leading zero bytes, upper case) because clients and OpenSSL pad it differently.
export function requestKey(der) {
  const b = Buffer.from(der);
  const req = expect(tlv(b, 0), 0x30);
  const tbs = expect(tlv(b, req.s), 0x30);
  let list = null;
  for (let p = tbs.s; p < tbs.e && !list; ) {
    const t = tlv(b, p);
    if (t.tag === 0x30) list = t; // the context-tagged fields (version, requestor, extensions) come before or after it
    p = t.e;
  }
  if (!list) throw new Error("no requestList");
  const first = expect(tlv(b, list.s), 0x30);
  const certId = expect(tlv(b, first.s), 0x30);
  const alg = expect(tlv(b, certId.s), 0x30);
  const oid = expect(tlv(b, alg.s), 0x06);
  const nameHash = expect(tlv(b, alg.e), 0x04);
  const keyHash = expect(tlv(b, nameHash.e), 0x04);
  const serial = expect(tlv(b, keyHash.e), 0x02);
  const oidHex = hex(b, oid.s, oid.e);
  let s = serial.s;
  while (s < serial.e - 1 && b[s] === 0) s++;
  return [
    OID_NAMES[oidHex] ?? oidHex,
    hex(b, nameHash.s, nameHash.e),
    hex(b, keyHash.s, keyHash.e),
    hex(b, s, serial.e).toUpperCase(),
  ].join(":");
}

// Standard or URL-safe base64, URL-encoded or not
function decodeGet(path) {
  let raw = path.replace(/^\/+/, "");
  if (raw.length === 0 || raw.length > 4096) throw new Error("no payload");
  raw = decodeURIComponent(raw).replace(/-/g, "+").replace(/_/g, "/");
  return Buffer.from(raw, "base64");
}

const decoded = new WeakMap(); // bundle -> Map(key -> Buffer), filled on first use

function find(bundle, key) {
  let m = decoded.get(bundle);
  if (!m) decoded.set(bundle, (m = new Map()));
  let r = m.get(key);
  if (!r) {
    const b64 = bundle.entries?.[key];
    if (!b64) return null;
    m.set(key, (r = Buffer.from(b64, "base64")));
  }
  return r;
}

const HEADERS = { "Content-Type": "application/ocsp-response", "X-Content-Type-Options": "nosniff" };

function reply(body, cache) {
  return { status: 200, headers: { ...HEADERS, "Cache-Control": cache }, body };
}

// method: "GET" | "POST" ...; path: URL path (GET payload); contentType/body: for POST; nowMs: injectable clock for tests.
// OCSP errors travel as HTTP 200 with an unsigned OCSPResponse, as RFC 6960 asks.
export function respond(bundle, { method, path, contentType, body, nowMs = Date.now() }) {
  let der;
  try {
    if (method === "GET") der = decodeGet(path);
    else if (method === "POST") {
      if (!/^application\/ocsp-request\b/i.test(contentType ?? "")) return { status: 415, headers: { "Content-Type": "text/plain" }, body: "unsupported media type" };
      der = Buffer.from(body ?? []);
      if (der.length === 0 || der.length > 8192) throw new Error("size");
    } else return { status: 405, headers: { Allow: "GET, POST", "Content-Type": "text/plain" }, body: "method not allowed" };
  } catch {
    return method === "GET" && path.replace(/^\/+/, "") === ""
      ? { status: 404, headers: { "Content-Type": "text/plain" }, body: "OCSP responder" }
      : reply(statusResponse(STATUS.malformed), "no-store");
  }

  let key;
  try { key = requestKey(der); } catch { return reply(statusResponse(STATUS.malformed), "no-store"); }

  // After validUntil the signed answers have run out: ask the client to try later (it then falls back to the CRL).
  if (!bundle.validUntil || nowMs / 1000 > bundle.validUntil) return reply(statusResponse(STATUS.tryLater), "no-store");

  const hit = find(bundle, key);
  if (!hit) return reply(statusResponse(STATUS.unauthorized), "no-store");

  const left = Math.max(0, Math.floor(bundle.validUntil - nowMs / 1000));
  return reply(hit, method === "GET" ? `public, max-age=${Math.min(3600, left)}` : "no-store");
}
