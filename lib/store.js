/**
 * Account store: scrypt-hashed passwords + persisted signing secret +
 * device roster, in one 0600 JSON file (atomic tmp+rename writes).
 * Hash parameters and the atomic-publish discipline follow the approach
 * documented by @xgone/dsh-remote (MIT); the layout below is this plugin's own.
 */
import { randomBytes, scryptSync, timingSafeEqual } from "node:crypto";
import { mkdirSync, readFileSync, renameSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";

const SCRYPT = { N: 16384, r: 8, p: 1, keylen: 64 };

export function defaultStorePath(dshHome) {
  return join(dshHome, "auth", "homegate-store.json");
}

/** `scrypt$N$r$p$salt$hash` (all base64url). */
export function hashPassword(password) {
  const salt = randomBytes(16);
  const hash = scryptSync(String(password), salt, SCRYPT.keylen, SCRYPT);
  return `scrypt$${SCRYPT.N}$${SCRYPT.r}$${SCRYPT.p}$${salt.toString("base64url")}$${hash.toString("base64url")}`;
}

export function verifyPassword(password, stored) {
  if (typeof stored !== "string") return false;
  const parts = stored.split("$");
  if (parts.length !== 6 || parts[0] !== "scrypt") return false;
  try {
    const [, N, r, p, saltB64, hashB64] = parts;
    const hash = scryptSync(String(password), Buffer.from(saltB64, "base64url"), SCRYPT.keylen, { N: +N, r: +r, p: +p, maxmem: 256 * 1024 * 1024 });
    const expected = Buffer.from(hashB64, "base64url");
    return hash.length === expected.length && timingSafeEqual(hash, expected);
  } catch {
    return false;
  }
}

export function generateSecret() {
  return randomBytes(32).toString("base64url");
}

const USERNAME_RE = /^[a-zA-Z0-9][a-zA-Z0-9._-]{1,31}$/;

export class AccountStore {
  /** @param {string} path store file path; created with 0600 on first save. */
  constructor(path) {
    this.path = path;
    this.data = { version: 1, secret: null, accounts: [], devices: [] };
    this.#load();
  }

  #load() {
    try {
      const raw = JSON.parse(readFileSync(this.path, "utf8"));
      if (raw && raw.version === 1 && Array.isArray(raw.accounts)) this.data = raw;
    } catch {
      // absent or unreadable: start empty; the first save publishes.
    }
  }

  #save() {
    mkdirSync(dirname(this.path), { recursive: true, mode: 0o700 });
    const tmp = `${this.path}.tmp`;
    writeFileSync(tmp, JSON.stringify(this.data, null, 2), { mode: 0o600 });
    renameSync(tmp, this.path); // same-directory rename is atomic on POSIX; Windows replaces atomically enough for a single writer
  }

  get ready() {
    return this.data.accounts.length > 0;
  }

  /** Persisted signing secret for gate session cookies (stable across restarts). */
  secret() {
    if (!this.data.secret) {
      this.data.secret = generateSecret();
      this.#save();
    }
    return Buffer.from(this.data.secret, "base64url");
  }

  list() {
    return this.data.accounts.map(({ username, role, totp, backupLeft }) => ({ username, role, mfa: Boolean(totp), backupLeft: backupLeft ?? 0 }));
  }

  get(username) {
    return this.data.accounts.find((account) => account.username === username) ?? null;
  }

  /** Create the first admin (bootstrap) or an additional account (admin call). */
  create(username, password, role = "user", { allowFirst = false } = {}) {
    if (!USERNAME_RE.test(String(username))) return { error: "bad-username" };
    if (String(password).length < 6) return { error: "weak-password" };
    if (this.data.accounts.length === 0 && !allowFirst && role !== "admin") role = "admin";
    if (this.get(username)) return { error: "exists" };
    const account = { username: String(username), hash: hashPassword(password), role: ["admin", "user", "guest"].includes(role) ? role : "user" };
    this.data.accounts.push(account);
    this.#save();
    return { account: this.#public(account) };
  }

  remove(username) {
    const before = this.data.accounts.length;
    this.data.accounts = this.data.accounts.filter((account) => account.username !== username);
    if (this.data.accounts.length === before) return false;
    this.#save();
    return true;
  }

  setPassword(username, password) {
    const account = this.get(username);
    if (!account || String(password).length < 6) return false;
    account.hash = hashPassword(password);
    this.#save();
    return true;
  }

  setRole(username, role) {
    const account = this.get(username);
    if (!account || !["admin", "user", "guest"].includes(role)) return false;
    account.role = role;
    this.#save();
    return true;
  }

  #public(account) {
    return { username: account.username, role: account.role, mfa: Boolean(account.totp) };
  }

  // ── MFA ──────────────────────────────────────────────────────────────────
  setTotp(username, secret, backupCodeHashes) {
    const account = this.get(username);
    if (!account) return false;
    account.totp = { secret };
    account.backup = backupCodeHashes;
    account.backupLeft = backupCodeHashes.length;
    this.#save();
    return true;
  }

  disableTotp(username) {
    const account = this.get(username);
    if (!account) return false;
    delete account.totp;
    delete account.backup;
    delete account.backupLeft;
    this.#save();
    return true;
  }

  /** Consume one backup code (hash compare against stored list). */
  useBackupCode(username, code, hashFn) {
    const account = this.get(username);
    if (!account?.backup) return false;
    const candidate = hashFn(code);
    const index = account.backup.indexOf(candidate);
    if (index === -1) return false;
    account.backup.splice(index, 1);
    account.backupLeft = account.backup.length;
    this.#save();
    return true;
  }

  // ── Device roster (mini plane) ───────────────────────────────────────────
  listDevices() {
    return this.data.devices.map(({ id, name, createdAt, lastSeenAt }) => ({ id, name, createdAt, lastSeenAt }));
  }

  addDevice(id, name, nowMs = Date.now()) {
    if (this.data.devices.some((device) => device.id === id)) return this.getDevice(id);
    const device = { id, name: String(name || "device").slice(0, 40), createdAt: nowMs, lastSeenAt: nowMs };
    this.data.devices.push(device);
    this.#save();
    return device;
  }

  getDevice(id) {
    return this.data.devices.find((device) => device.id === id) ?? null;
  }

  touchDevice(id, nowMs = Date.now()) {
    const device = this.getDevice(id);
    if (!device) return;
    device.lastSeenAt = nowMs;
    // throttled persistence handled by the caller; keep in-memory fresh
  }

  removeDevice(id) {
    const before = this.data.devices.length;
    this.data.devices = this.data.devices.filter((device) => device.id !== id);
    if (this.data.devices.length === before) return false;
    this.#save();
    return true;
  }
}
