import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import {
  canonicalAuthority,
  cookieHeaderSet,
  cookieValueOf,
  decodeDshAuthCookie,
  decodeGateSessionCookie,
  dshAuthCookieName,
  encodeDshAuthCookie,
  encodeGateSessionCookie,
  readBrowserAuthSecret,
} from "../lib/auth-cookie.js";

const secret = randomBytes(32);
const NOW = 1_800_000_000_000;

test("canonicalAuthority normalizes like WHATWG URL", () => {
  assert.equal(canonicalAuthority("Example.COM:3080"), "example.com:3080");
  assert.equal(canonicalAuthority("127.0.0.1"), "127.0.0.1");
  assert.equal(canonicalAuthority("bad host"), null);
  assert.equal(canonicalAuthority(""), null);
});

test("core cookie: name binds the authority hash", () => {
  const name = dshAuthCookieName("192.168.0.35:3080");
  assert.match(name, /^dsh-auth-[A-Za-z0-9_-]{43}$/);
  assert.notEqual(name, dshAuthCookieName("127.0.0.1:3080"));
});

test("core cookie: mint → decode roundtrip", () => {
  const { name, value } = encodeDshAuthCookie("192.168.0.35:3080", secret, 60_000, NOW);
  const payload = decodeDshAuthCookie(value, secret, "192.168.0.35:3080", NOW + 1000);
  assert.equal(payload.authority, "192.168.0.35:3080");
  assert.equal(payload.version, 1);
  assert.equal(decodeDshAuthCookie(value, secret, "192.168.0.35:3080", NOW + 61_000), null); // expired
  assert.equal(decodeDshAuthCookie(value, randomBytes(32), "192.168.0.35:3080", NOW), null); // wrong secret
  assert.equal(decodeDshAuthCookie(value, secret, "evil.example:3080", NOW), null); // wrong authority
});

test("core cookie: tamper with body fails signature", () => {
  const { value } = encodeDshAuthCookie("host:1", secret, 60_000, NOW);
  const [, body, sig] = value.split(".");
  const forged = Buffer.from(JSON.stringify({ version: 1, authority: "attacker:2", issuedAt: NOW, expiresAt: NOW + 999999 })).toString("base64url");
  assert.equal(decodeDshAuthCookie(`v1.${forged}.${sig}`, secret, "attacker:2", NOW), null);
});

test("core cookie: mint window is capped at 30 days", () => {
  const { cookie } = encodeDshAuthCookie("host:1", secret, 400 * 24 * 3600 * 1000, NOW);
  const maxAge = Number(/Max-Age=(\d+)/.exec(cookie)[1]);
  assert.equal(maxAge, 30 * 24 * 3600);
  const { value } = encodeDshAuthCookie("host:1", secret, 400 * 24 * 3600 * 1000, NOW);
  assert.ok(decodeDshAuthCookie(value, secret, "host:1", NOW)); // the stored window is within the cap
});

test("readBrowserAuthSecret validates the record shape", () => {
  const b64 = secret.toString("base64url");
  assert.deepEqual([...readBrowserAuthSecret({ kind: "grant", payload: { version: 1, secret: b64 } })], [...secret]);
  assert.equal(readBrowserAuthSecret({ kind: "other", payload: { version: 1, secret: b64 } }), null);
  assert.equal(readBrowserAuthSecret({ kind: "grant", payload: { version: 2, secret: b64 } }), null);
  assert.equal(readBrowserAuthSecret({ kind: "grant", payload: { version: 1, secret: "short" } }), null);
  assert.equal(readBrowserAuthSecret(null), null);
});

test("gate cookie: encode → decode + tamper + expiry", () => {
  const account = { username: "yoon", role: "admin" };
  const { name, value, cookie } = encodeGateSessionCookie("hg_session", secret, account, 1000, { nowMs: NOW });
  const header = `other=1; ${name}=${value}; another=2`;
  const payload = decodeGateSessionCookie("hg_session", secret, header, NOW + 500);
  assert.equal(payload.u, "yoon");
  assert.equal(payload.role, "admin");
  assert.equal(decodeGateSessionCookie("hg_session", secret, header, NOW + 1500), null);
  assert.equal(decodeGateSessionCookie("hg_session", randomBytes(32), header, NOW), null);
  assert.equal(decodeGateSessionCookie("hg_session", secret, `hg_session=v1.abc.deadbeef;`, NOW), null);
  assert.ok(cookie.includes("HttpOnly") && cookie.includes("SameSite=Lax"));
  assert.ok(!cookie.includes("Secure"));
  const secure = encodeGateSessionCookie("hg_session", secret, account, 1000, { secure: true, nowMs: NOW });
  assert.ok(secure.cookie.includes("; Secure"));
});

test("cookieValueOf: exact-name first-match semantics", () => {
  assert.equal(cookieValueOf("a=1; b=2; a=3", "a"), "1");
  assert.equal(cookieValueOf("a=1", "b"), null);
});

test("cookieHeaderSet replaces EVERY stale segment (core reads the first)", () => {
  const header = cookieHeaderSet("a=stale; keep=1; a=stale2", "a", "fresh");
  assert.equal(header, "keep=1; a=fresh");
  assert.equal(cookieValueOf(header, "a"), "fresh");
  assert.equal(cookieHeaderSet(undefined, "a", "fresh"), "a=fresh");
});
