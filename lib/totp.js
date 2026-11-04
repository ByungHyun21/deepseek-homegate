/**
 * RFC 4226 HOTP / RFC 6238 TOTP with RFC 4648 base32, plus backup codes.
 * Pure node:crypto — no dependencies.
 */
import { createHmac, randomBytes, randomInt, timingSafeEqual } from "node:crypto";

const B32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

/** Encode random bytes as a base32 secret (default 160-bit, RFC 6238 §4). */
export function generateTotpSecret(bytes = 20) {
  const buf = randomBytes(bytes);
  let bits = "";
  for (const byte of buf) bits += byte.toString(2).padStart(8, "0");
  let out = "";
  for (let i = 0; i + 5 <= bits.length; i += 5) out += B32_ALPHABET[parseInt(bits.slice(i, i + 5), 2)];
  return out;
}

/** Decode base32 (case-insensitive, padding/whitespace tolerated). null when invalid. */
export function base32Decode(input) {
  if (typeof input !== "string") return null;
  const clean = input.toUpperCase().replace(/=+$/g, "").replace(/[\s-]/g, "");
  if (clean.length === 0) return null;
  let bits = "";
  for (const char of clean) {
    const idx = B32_ALPHABET.indexOf(char);
    if (idx === -1) return null;
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) bytes.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(bytes);
}

/** RFC 4226 HOTP over a decoded secret buffer. */
export function hotp(key, counter, digits = 6) {
  const buf = Buffer.alloc(8);
  buf.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  buf.writeUInt32BE(counter >>> 0, 4);
  const digest = createHmac("sha1", key).update(buf).digest();
  const offset = digest[digest.length - 1] & 0x0f;
  const code = ((digest[offset] & 0x7f) << 24 | digest[offset + 1] << 16 | digest[offset + 2] << 8 | digest[offset + 3]) % 10 ** digits;
  return String(code).padStart(digits, "0");
}

/**
 * Verify a TOTP code with a ±step window (default ±1 step of 30 s).
 * Returns { valid, stepOffset } — never early-exits so timing cannot leak the
 * matching window slot.
 */
export function verifyTotp(base32Secret, code, nowMs = Date.now(), { stepSeconds = 30, window = 1, digits = 6 } = {}) {
  const key = base32Decode(base32Secret);
  if (key === null || key.length === 0) return { valid: false, stepOffset: null };
  const normalized = String(code ?? "").replace(/\s/g, "");
  if (!new RegExp(`^\\d{${digits}}$`).test(normalized)) return { valid: false, stepOffset: null };
  const current = Math.floor(nowMs / 1000 / stepSeconds);
  let matched = null;
  for (let offset = -window; offset <= window; offset++) {
    if (current + offset < 0) continue; // pre-epoch slots do not exist
    const expected = hotp(key, current + offset, digits);
    const a = Buffer.from(expected);
    const b = Buffer.from(normalized);
    if (a.length === b.length && timingSafeEqual(a, b)) matched = offset; // keep scanning: constant-time over the window
  }
  return { valid: matched !== null, stepOffset: matched };
}

/** otpauth:// URI for authenticator enrollment. */
export function otpauthUri({ secret, account, issuer = "DeepSeek Homegate", digits = 6, period = 30 }) {
  const params = new URLSearchParams({ secret, issuer, algorithm: "SHA1", digits: String(digits), period: String(period) });
  return `otpauth://totp/${encodeURIComponent(issuer)}:${encodeURIComponent(account)}?${params}`;
}

/** 10 single-use recovery codes (`hg-` + 10 base36 chars). */
export function generateBackupCodes(count = 10) {
  const alphabet = "abcdefghijklmnopqrstuvwxyz0123456789";
  const codes = [];
  for (let i = 0; i < count; i++) {
    let body = "";
    for (let j = 0; j < 10; j++) body += alphabet[randomInt(alphabet.length)];
    codes.push(`hg-${body}`);
  }
  return codes;
}

/** Deterministic hash for at-rest backup-code storage. */
export function hashBackupCode(code, pepper) {
  return createHmac("sha256", pepper).update(String(code).trim().toLowerCase()).digest("base64url");
}
