import { test } from "node:test";
import assert from "node:assert/strict";
import { classify, createRateLimiter, isLoopbackSocket } from "../lib/gate.js";

test("classify: own plane is public", () => {
  for (const pathname of ["/auth/login", "/auth/me", "/auth/admin", "/mini/p", "/mini/invite"]) {
    assert.equal(classify({ pathname, hasGateSession: false }).action, "public", pathname);
  }
});

test("classify: authenticated traffic passes, anonymous gets challenged", () => {
  assert.equal(classify({ pathname: "/api/session.list", hasGateSession: true }).action, "pass");
  assert.equal(classify({ pathname: "/", hasGateSession: true }).action, "pass");
  assert.equal(classify({ pathname: "/", hasGateSession: false }).action, "unauthorized");
  assert.equal(classify({ pathname: "/api/x", hasGateSession: false }).action, "unauthorized");
});

test("rate limiter: fixed window per key", () => {
  const limiter = createRateLimiter({ maxAttempts: 3, windowMs: 1000 });
  const now = 1000;
  assert.equal(limiter.check("ip|u", now), true);
  limiter.noteFailure("ip|u", now);
  limiter.noteFailure("ip|u", now);
  assert.equal(limiter.check("ip|u", now), true); // 2 of 3
  limiter.noteFailure("ip|u", now);
  assert.equal(limiter.check("ip|u", now), false);
  assert.ok(limiter.retryAfterMs("ip|u", now) > 0);
  assert.equal(limiter.check("other|u", now), true); // per-key isolation
  assert.equal(limiter.check("ip|u", now + 1001), true); // window rolled
});

test("rate limiter: success resets the counter", () => {
  const limiter = createRateLimiter({ maxAttempts: 2, windowMs: 1000 });
  limiter.noteFailure("k", 1000);
  limiter.reset("k");
  assert.equal(limiter.check("k", 1000), true);
  limiter.noteFailure("k", 1000);
  assert.equal(limiter.check("k", 1000), true); // fresh window of 2 begins after reset
});

test("isLoopbackSocket: v4/v6 loopback only", () => {
  assert.equal(isLoopbackSocket({ remoteAddress: "127.0.0.1" }), true);
  assert.equal(isLoopbackSocket({ remoteAddress: "127.5.5.5" }), true);
  assert.equal(isLoopbackSocket({ remoteAddress: "::1" }), true);
  assert.equal(isLoopbackSocket({ remoteAddress: "::ffff:127.0.0.1" }), true);
  assert.equal(isLoopbackSocket({ remoteAddress: "192.168.0.7" }), false);
  assert.equal(isLoopbackSocket({}), false);
});
