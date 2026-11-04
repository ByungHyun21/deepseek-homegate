/**
 * Gate decisions — pure functions (no node deps) so the whole auth
 * classification is unit-testable without a live webserver.
 */

/** Paths the gate never wraps (its own plane + public host assets). */
export const PUBLIC_PREFIXES = ["/auth/", "/mini/"];
export const PUBLIC_EXACT = new Set(["/auth/login", "/auth/mfa/login", "/auth/bootstrap", "/auth/logout", "/auth/me", "/mini/p"]);

/** Loopback / bind-address detection for the bootstrap restriction. */
export function isLoopbackSocket(socket) {
  const address = socket?.remoteAddress ?? "";
  return address === "127.0.0.1" || address === "::1" || address === "::ffff:127.0.0.1" || address.startsWith("127.");
}

/**
 * Classify one gated HTTP request.
 * @param {{pathname:string, hasGateSession:boolean, isUpgrade?:boolean}} request
 * @returns {{action:'public'|'pass'|'login-page'|'forbidden'|'unauthorized'}}
 */
export function classify({ pathname, hasGateSession }) {
  if (PUBLIC_EXACT.has(pathname)) return { action: "public" };
  for (const prefix of PUBLIC_PREFIXES) {
    if (pathname.startsWith(prefix)) {
      // The mini plane carries its own device cookie; treat everything under
      // /mini/ as public-to-this-gate (mini.js enforces its own auth).
      return { action: "public" };
    }
  }
  if (hasGateSession) return { action: "pass" };
  // Unauthenticated: browsers navigating to pages get the login page; API-ish
  // requests get a small 401 JSON so fetch callers fail cleanly.
  return { action: "unauthorized" };
}

/**
 * Fixed-window login rate limiter (per IP+username key).
 * createRateLimiter({maxAttempts, windowMs}) => {check(key), noteFailure(key), reset(key)}
 */
export function createRateLimiter({ maxAttempts = 8, windowMs = 15 * 60 * 1000 } = {}) {
  const attempts = new Map();
  let lastSweep = 0;
  const sweep = (now) => {
    if (now - lastSweep < windowMs) return;
    lastSweep = now;
    for (const [key, entry] of attempts) if (entry.resetAt <= now) attempts.delete(key);
  };
  return {
    check(key, now = Date.now()) {
      sweep(now);
      const entry = attempts.get(key);
      return !entry || entry.count < maxAttempts;
    },
    retryAfterMs(key, now = Date.now()) {
      const entry = attempts.get(key);
      return entry && entry.count >= maxAttempts ? Math.max(0, entry.resetAt - now) : 0;
    },
    noteFailure(key, now = Date.now()) {
      const entry = attempts.get(key);
      if (!entry || entry.resetAt <= now) attempts.set(key, { count: 1, resetAt: now + windowMs });
      else entry.count += 1;
    },
    reset(key) {
      attempts.delete(key);
    },
  };
}

/** Minimal body reader with a hard cap; parses JSON, null on overflow/invalid. */
export async function readJsonBody(req, limitBytes = 16 * 1024) {
  const chunks = [];
  let size = 0;
  for await (const chunk of req) {
    size += chunk.length;
    if (size > limitBytes) return null;
    chunks.push(chunk);
  }
  try {
    return JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return null;
  }
}
