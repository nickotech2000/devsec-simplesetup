/*------------------------------------------------
Author  : Nicko Satria Utama
Company : Agantra Inovatif OU
Email   : nicko@nextmantra.com
------------------------------------------------*/

import bundle from "../data/ocsp-bundle.json" with { type: "json" };
import { respond } from "../lib/ocsp.mjs";

export const config = { path: "/*" };

export default async (req) => {
  const method = req.method;
  const body = method === "POST" ? new Uint8Array(await req.arrayBuffer()) : undefined;
  const r = respond(bundle, {
    method,
    path: new URL(req.url).pathname,
    contentType: req.headers.get("content-type"),
    body,
  });
  return new Response(r.body, { status: r.status, headers: r.headers });
};
