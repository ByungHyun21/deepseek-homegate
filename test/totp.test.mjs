import { test } from "node:test";
import assert from "node:assert/strict";
import { base32Decode, generateBackupCodes, generateTotpSecret, hashBackupCode, hotp, otpauthUri, verifyTotp } from "../lib/totp.js";

// RFC 6238 Appendix B vector: SHA1 key "12345678901234567890" (base32
// GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ), 8-digit codes; T=59s => 94287082.
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";

test("base32 decodes the RFC 6238 test key", () => {
  assert.equal(base32Decode(RFC_SECRET).toString("ascii"), "12345678901234567890");
});

test("hotp matches RFC 4226 counter=0 (6 digits)", () => {
  assert.equal(hotp(base32Decode(RFC_SECRET), 0, 6), "755224");
});

test("totp verifies RFC vector at T=59s (6-digit tail of 94287082)", () => {
  const result = verifyTotp(RFC_SECRET, "287082", 59_000, { digits: 6 });
  assert.equal(result.valid, true);
});

test("totp rejects stale code outside the window", () => {
  assert.equal(verifyTotp(RFC_SECRET, "287082", 59_000 + 120_000).valid, false);
});

test("totp accepts one step early/late (window=1)", () => {
  assert.equal(verifyTotp(RFC_SECRET, "287082", 59_000 + 30_000).valid, true);
  assert.equal(verifyTotp(RFC_SECRET, "287082", 59_000 - 30_000).valid, true);
});

test("garbage never validates", () => {
  for (const bad of ["", "abcdef", "12345", "000000", null, undefined, "12 34 56".replace(/ /g, "x")]) {
    assert.equal(verifyTotp(RFC_SECRET, bad, 59_000).valid, false, String(bad));
  }
  assert.equal(verifyTotp("!!!not-base32!!!", "287082", 59_000).valid, false);
});

test("generated secrets are valid base32 and self-consistent", () => {
  const secret = generateTotpSecret();
  const now = Date.now();
  const forward = verifyTotp(secret, hotp(base32Decode(secret), Math.floor(now / 30_000)), now);
  assert.equal(forward.valid, true);
});

test("backup codes are single-use-hashable and peppered", () => {
  const codes = generateBackupCodes();
  assert.equal(codes.length, 10);
  assert.match(codes[0], /^hg-[a-z0-9]{10}$/);
  const pepper = Buffer.from("0".repeat(32));
  assert.equal(hashBackupCode(codes[0], pepper), hashBackupCode(codes[0].toUpperCase(), pepper)); // normalize compare
  assert.notEqual(hashBackupCode(codes[0], pepper), hashBackupCode(codes[1], pepper));
});

test("otpauth uri carries secret and issuer", () => {
  const uri = otpauthUri({ secret: RFC_SECRET, account: "admin" });
  assert.match(uri, /^otpauth:\/\/totp\//);
  assert.ok(uri.includes(`secret=${RFC_SECRET}`));
});
