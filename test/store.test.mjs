import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { AccountStore, generateSecret, hashPassword, verifyPassword } from "../lib/store.js";
import { generateBackupCodes, hashBackupCode } from "../lib/totp.js";

const dir = () => mkdtempSync(join(tmpdir(), "homegate-"));

test("scrypt roundtrip + wrong password + tamper-safe formats", () => {
  const stored = hashPassword("correct horse");
  assert.ok(stored.startsWith("scrypt$16384$8$1$"));
  assert.equal(verifyPassword("correct horse", stored), true);
  assert.equal(verifyPassword("Correct horse", stored), false);
  assert.equal(verifyPassword("correct horse ", stored), false);
  assert.equal(verifyPassword("x", "not-a-hash"), false);
  assert.equal(verifyPassword("x", "scrypt$1$1$1$AAA$BBB"), false);
});

test("two hashes of the same password differ (salted)", () => {
  assert.notEqual(hashPassword("same"), hashPassword("same"));
});

test("store: create/list/get/remove + first-admin rule", () => {
  const store = new AccountStore(join(dir(), "store.json"));
  assert.equal(store.ready, false);
  const created = store.create("yoon", "secret123", "user", { allowFirst: true });
  assert.equal(created.account.role, "user");
  assert.equal(store.ready, true);
  assert.equal(store.create("yoon", "another1").error, "exists");
  assert.equal(store.create("y", "abcdefgh").error, "bad-username");
  assert.equal(store.create("good", "123").error, "weak-password");
  assert.equal(store.list()[0].username, "yoon");
  assert.equal(store.remove("yoon"), true);
  assert.equal(store.remove("yoon"), false);
  assert.equal(store.ready, false);
});

test("store: secret persists across reloads", () => {
  const path = join(dir(), "store.json");
  const a = new AccountStore(path);
  const secretA = a.secret();
  const b = new AccountStore(path);
  assert.deepEqual(b.secret(), secretA);
  assert.equal(secretA.length, 32);
});

test("store: file written 0600 and JSON-clean", () => {
  const path = join(dir(), "store.json");
  const store = new AccountStore(path);
  store.create("admin", "password1", "admin");
  const mode = statSync(path).mode & 0o777;
  if (process.platform === "win32") {
    assert.ok([0o644, 0o666].includes(mode), `unexpected Windows mode ${mode.toString(8)}`); // NTFS ACLs do not map; node reports a nominal mode
  } else {
    assert.equal(mode, 0o600, `POSIX store file must be 0600, got ${mode.toString(8)}`);
  }
  const raw = JSON.parse(readFileSync(path, "utf8"));
  assert.equal(raw.accounts[0].username, "admin");
  assert.ok(raw.accounts[0].hash.startsWith("scrypt$"));
  assert.ok(!JSON.stringify(raw).includes("password1"));
});

test("store: MFA + single-use backup codes", () => {
  const store = new AccountStore(join(dir(), "store.json"));
  const pepper = store.secret();
  store.create("admin", "password1", "admin");
  const codes = generateBackupCodes();
  store.setTotp("admin", "JBSWY3DPEHPK3PXP", codes.map((c) => hashBackupCode(c, pepper)));
  assert.equal(store.list()[0].mfa, true);
  assert.equal(store.useBackupCode("admin", codes[0], (c) => hashBackupCode(c, pepper)), true);
  assert.equal(store.useBackupCode("admin", codes[0], (c) => hashBackupCode(c, pepper)), false); // consumed
  assert.equal(store.list()[0].backupLeft, 9);
  store.disableTotp("admin");
  assert.equal(store.list()[0].mfa, false);
});

test("store: device roster add/list/touch/remove", () => {
  const store = new AccountStore(join(dir(), "store.json"));
  const device = store.addDevice("abc123", "iPhone");
  assert.equal(device.name, "iPhone");
  assert.equal(store.listDevices().length, 1);
  assert.equal(store.getDevice("abc123").createdAt, device.createdAt);
  assert.equal(store.removeDevice("abc123"), true);
  assert.equal(store.getDevice("abc123"), null);
});

test("generateSecret is 32 bytes base64url", () => {
  const raw = generateSecret();
  assert.equal(Buffer.from(raw, "base64url").length, 32);
});
