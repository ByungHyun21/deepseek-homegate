/**
 * Cookie codecs.
 *
 * 1) The CORE's browser-session cookie (`dsh-auth-<b64url(sha256(authority))>`)
 *    mirrored from dsh core `client-connection` browser-auth v1 so this plugin
 *    can mint cookies the core accepts (the core's persisted signing secret is
 *    read from the credential record `client-connection/browser-session`).
 *    Wire layout (v1): `v1.<base64url(json{version,authority,issuedAt,expiresAt})>.<base64url(HMAC-SHA256(body, secret))>`.
 *
 * 2) This plugin's OWN gate session cookie: same envelope shape, its own
 *    payload {u, role, iat, exp} and the plugin's persisted secret.
 *
 * Layout notes (2) and the attribute sets mirror dsh core's serialization on
 * purpose; structure studied in @xgone/dsh-remote (MIT) which documents the
 * same mirror of packages/client/connection/src/browser-auth.ts.
 */
import { createHash, createHmac, timingSafeEqual } from "node:crypto";

/** Credential record key holding client-connection's persistent signing secret. */
export const BROWSER_SESSION_RECORD_KEY = "client-connection/browser-session";
/** client-connection.cookieMaxAgeDays default — the core rejects longer windows. */
export const BROWSER_COOKIE_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000;

/** Canonical request authority as the core derives it from a Host header. */
export function canonicalAuthority(host) {
  if (typeof host !== "string" || host === "") return null;
  try {
    return new URL(`http://${host}`).host;
  } catch {
    return null;
  }
}

/** `dsh-auth-` + base64url(sha256(authority)) — the core's cookie naming. */
export function dshAuthCookieName(authority) {
  return "dsh-auth-" + createHash("sha256").update(authority).digest("base64url");
}

/** Extract the 32-byte signing secret from a credentials record. */
export function readBrowserAuthSecret(record) {
  if (record === null || typeof record !== "object") return null;
  if (record.kind !== "grant" || record.payload?.version !== 1) return null;
  if (typeof record.payload.secret !== "string") return null;
  const secret = Buffer.from(record.payload.secret, "base64url");
  return secret.byteLength === 32 ? secret : null;
}

function signBody(body, secret) {
  return createHmac("sha256", secret).update(body).digest("base64url");
}

/** Mint one core-accepted dsh-auth cookie for `authority`. */
export function encodeDshAuthCookie(authority, secret, ttlMs, nowMs = Date.now()) {
  const expiresAt = nowMs + Math.min(ttlMs, BROWSER_COOKIE_MAX_AGE_MS);
  const body = Buffer.from(JSON.stringify({ version: 1, authority, issuedAt: nowMs, expiresAt }), "utf8").toString("base64url");
  const name = dshAuthCookieName(authority);
  const value = `v1.${body}.${signBody(body, secret)}`;
  return { name, value, cookie: `${name}=${value}; Max-Age=${Math.floor(Math.min(ttlMs, BROWSER_COOKIE_MAX_AGE_MS) / 1000)}; Path=/; Expires=${new Date(expiresAt).toUTCString()}; HttpOnly; SameSite=Strict` };
}

/** Verify a core-or-minted cookie value for `authority`; payload or null. */
export function decodeDshAuthCookie(value, secret, authority, nowMs = Date.now()) {
  const parts = String(value ?? "").split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return null;
  const [, body, sigB64] = parts;
  let sig, expected;
  try {
    sig = Buffer.from(sigB64, "base64url");
    expected = Buffer.from(signBody(body, secret), "base64url");
  } catch {
    return null;
  }
  if (sig.length !== expected.length || !timingSafeEqual(sig, expected)) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (payload?.version !== 1 || payload.authority !== authority) return null;
  if (!Number.isSafeInteger(payload.issuedAt) || !Number.isSafeInteger(payload.expiresAt)) return null;
  return payload.issuedAt <= nowMs && payload.expiresAt > nowMs
    && payload.expiresAt > payload.issuedAt
    && payload.expiresAt - payload.issuedAt <= BROWSER_COOKIE_MAX_AGE_MS ? payload : null;
}

/** Gate session cookie: `v1.<b64url(json{u,role,iat,exp})>.<hmac>`. */
export function encodeGateSessionCookie(name, secret, account, ttlMs, { secure = false, nowMs = Date.now() } = {}) {
  const exp = nowMs + ttlMs;
  const body = Buffer.from(JSON.stringify({ u: account.username, role: account.role, iat: nowMs, exp }), "utf8").toString("base64url");
  const value = `v1.${body}.${signBody(body, secret)}`;
  const attrs = `Max-Age=${Math.floor(ttlMs / 1000)}; Path=/; Expires=${new Date(exp).toUTCString()}; HttpOnly; SameSite=Lax`;
  return { name, value, cookie: `${name}=${value}; ${attrs}${secure ? "; Secure" : ""}` };
}

/** Verify a gate session cookie; payload {u, role, iat, exp} or null. */
export function decodeGateSessionCookie(name, secret, cookieHeader, nowMs = Date.now()) {
  const value = cookieValueOf(cookieHeader, name);
  if (value === null) return null;
  const parts = value.split(".");
  if (parts.length !== 3 || parts[0] !== "v1") return null;
  const [, body, sigB64] = parts;
  let sig, expected;
  try {
    sig = Buffer.from(sigB64, "base64url");
    expected = Buffer.from(signBody(body, secret), "base64url");
  } catch {
    return null;
  }
  if (sig.length !== expected.length || !timingSafeEqual(sig, expected)) return null;
  let payload;
  try {
    payload = JSON.parse(Buffer.from(body, "base64url").toString("utf8"));
  } catch {
    return null;
  }
  if (!payload || typeof payload.u !== "string" || !Number.isSafeInteger(payload.exp)) return null;
  return payload.exp > nowMs && payload.iat <= nowMs ? payload : null;
}

/** Exact-name cookie value from a raw Cookie header. */
export function cookieValueOf(cookieHeader, name) {
  for (const segment of String(cookieHeader ?? "").split(";")) {
    const at = segment.indexOf("=");
    if (at === -1 || segment.slice(0, at).trim() !== name) continue;
    return segment.slice(at + 1).trim();
  }
  return null;
}

/**
 * Replace every segment of `name` in a Cookie header (the core reads the
 * FIRST match, so a stale segment would shadow a freshly minted value).
 */
export function cookieHeaderSet(cookieHeader, name, value) {
  const kept = [];
  for (const segment of String(cookieHeader ?? "").split(";")) {
    const trimmed = segment.trim();
    if (trimmed === "") continue;
    const at = trimmed.indexOf("=");
    if (at !== -1 && trimmed.slice(0, at).trim() === name) continue;
    kept.push(trimmed);
  }
  kept.push(`${name}=${value}`);
  return kept.join("; ");
}

/** Constant-time compare of two equal-domain secrets (signature material). */
export function safeEqualString(a, b) {
  const ba = Buffer.from(String(a));
  const bb = Buffer.from(String(b));
  return ba.length === bb.length && timingSafeEqual(ba, bb);
}
