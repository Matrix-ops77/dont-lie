/**
 * don't-lie witness-service — Cloudflare Worker.
 *
 * Public, no-signup notary that co-signs receipt hashes. Anyone can
 * POST a hash + their operator key_id and get back a signed
 * attestation that proves "at time T, this hash existed at this
 * service." The attestation can be verified offline against the
 * public key returned by /pubkey.
 *
 * Mirrors the Python witness_service.py in the main package so that
 * any client that integrates with the local service also works
 * against this hosted version.
 *
 * Endpoints:
 *   GET  /             service banner
 *   GET  /healthz      liveness check
 *   GET  /pubkey       { service, key_id, public_key_pem }
 *   GET  /stats        { requests, attestations }
 *   GET  /attestations last 100 attestations (public ledger)
 *   POST /attest       body: { receipt_sha256, operator_key_id,
 *                             parent_sha256?, nonce? } -> signed att.
 *
 * Env (set via `wrangler secret put`):
 *   WITNESS_PRIVATE_HEX  32-byte Ed25519 private key (hex)
 *   WITNESS_KEY_ID       short key id (printed in attestations)
 *   WITNESS_PUB_PEM      matching public key in PEM form
 */

const SERVICE_NAME = "dontlie-witness-service";
const SERVICE_VERSION = "0.1.0";

// --- key state -------------------------------------------------------------

let cachedKey = null;
let attestations = []; // ring buffer of the last 100
let requestCount = 0;

async function getKey(env) {
  if (cachedKey) return cachedKey;
  // Private key is 32 raw bytes for Ed25519. We import it as pkcs8.
  const privHex = env.WITNESS_PRIVATE_HEX;
  if (!privHex) {
    throw new Error("WITNESS_PRIVATE_HEX secret not set");
  }
  const raw = hexToBytes(privHex);
  // WebCrypto Ed25519 expects PKCS8 wrapping for importKey. Build it.
  // PKCS8 prefix for Ed25519:
  //   30 2e 02 01 00 30 05 06 03 2b 65 70 04 22 04 20 <32 bytes>
  const pkcs8 = new Uint8Array([
    0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70,
    0x04, 0x22, 0x04, 0x20,
    ...raw,
  ]);
  const cryptoKey = await crypto.subtle.importKey(
    "pkcs8",
    pkcs8,
    { name: "Ed25519" },
    false,
    ["sign"],
  );
  cachedKey = cryptoKey;
  return cryptoKey;
}

function hexToBytes(hex) {
  if (hex.length % 2) throw new Error("odd-length hex");
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    out[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return out;
}

function bytesToHex(bytes) {
  return [...new Uint8Array(bytes)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

function b64encode(bytes) {
  let s = "";
  for (const b of new Uint8Array(bytes)) s += String.fromCharCode(b);
  return btoa(s);
}

// --- canonical JSON (sorted keys, no spaces) --------------------------------

function canonicalJSON(obj) {
  if (obj === null) return "null";
  if (typeof obj === "number") return String(obj);
  if (typeof obj === "string") return JSON.stringify(obj);
  if (Array.isArray(obj)) {
    return "[" + obj.map(canonicalJSON).join(",") + "]";
  }
  if (typeof obj === "object") {
    const keys = Object.keys(obj).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalJSON(obj[k])).join(",") + "}";
  }
  throw new Error("non-JSON-serializable value");
}

// --- response helpers -------------------------------------------------------

function jsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body, null, 2), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

function textResponse(body, status = 200) {
  return new Response(body, {
    status,
    headers: {
      "Content-Type": "text/plain; charset=utf-8",
      "Access-Control-Allow-Origin": "*",
    },
  });
}

function banner() {
  return {
    service: SERVICE_NAME,
    version: SERVICE_VERSION,
    key_id: globalThis.__keyId || "(set WITNESS_KEY_ID)",
    ok: true,
    endpoints: {
      "GET  /": "this banner",
      "GET  /healthz": "liveness check (same as /)",
      "GET  /pubkey": "the service's signing public key (PEM)",
      "GET  /stats": "request and attestation counts",
      "GET  /attestations": "the last 100 attestations (public ledger)",
      "POST /attest": "request a co-signature for a receipt hash",
    },
    docs: "https://github.com/Matrix-ops77/dontlie/blob/main/docs/WITNESS_SERVICE.md",
  };
}

// --- handler ----------------------------------------------------------------

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          "Access-Control-Allow-Origin": "*",
          "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type",
        },
      });
    }

    // /, /healthz, /health
    if (request.method === "GET" && (path === "/" || path === "/healthz" || path === "/health")) {
      requestCount++;
      return jsonResponse(banner());
    }

    // /pubkey
    if (request.method === "GET" && path === "/pubkey") {
      requestCount++;
      return jsonResponse({
        service: SERVICE_NAME,
        key_id: env.WITNESS_KEY_ID,
        public_key_pem: env.WITNESS_PUB_PEM,
      });
    }

    // /stats
    if (request.method === "GET" && path === "/stats") {
      return jsonResponse({
        requests: requestCount,
        attestations: attestations.length,
      });
    }

    // /attestations (public ledger)
    if (request.method === "GET" && path === "/attestations") {
      return jsonResponse({ attestations: attestations.slice(-100) });
    }

    // POST /attest
    if (request.method === "POST" && path === "/attest") {
      requestCount++;
      let body;
      try {
        body = await request.json();
      } catch (e) {
        return jsonResponse({ error: `invalid JSON: ${e.message}` }, 400);
      }
      const receipt_sha = body.receipt_sha256 || "";
      const operator_key_id = body.operator_key_id || "";
      const parent_sha = body.parent_sha256 || null;
      const nonce = body.nonce || randomHex(16);

      if (!receipt_sha || !operator_key_id) {
        return jsonResponse(
          { error: "receipt_sha256 and operator_key_id are required" },
          400,
        );
      }
      if (!/^[0-9a-fA-F]{64}$/.test(receipt_sha)) {
        return jsonResponse(
          { error: "receipt_sha256 is not a valid SHA-256 hex digest" },
          400,
        );
      }

      const now = new Date().toISOString();
      const service_key_id = env.WITNESS_KEY_ID;
      // Canonical message. The Python service signs this exact JSON.
      const msg = canonicalJSON({
        receipt_sha256: receipt_sha,
        operator_key_id,
        parent_sha256: parent_sha || "",
        nonce,
        service: SERVICE_NAME,
        service_version: SERVICE_VERSION,
        service_key_id,
        issued_at: now,
      });

      let signature;
      try {
        const key = await getKey(env);
        const sigBytes = await crypto.subtle.sign("Ed25519", key, new TextEncoder().encode(msg));
        signature = b64encode(sigBytes);
      } catch (e) {
        return jsonResponse({ error: `signing failed: ${e.message}` }, 500);
      }

      const attestation = {
        service: SERVICE_NAME,
        service_version: SERVICE_VERSION,
        service_key_id,
        issued_at: now,
        receipt_sha256: receipt_sha,
        operator_key_id,
        parent_sha256: parent_sha,
        nonce,
        signature,
      };
      attestations.push(attestation);
      if (attestations.length > 100) attestations.shift();
      return jsonResponse(attestation);
    }

    return jsonResponse({ error: "not found" }, 404);
  },
};

function randomHex(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);
  return bytesToHex(b);
}
