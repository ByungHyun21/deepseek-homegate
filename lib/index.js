/**
 * deepseek-homegate — account login gate + paired-device remote access for
 * the DeepSeek Harness web surface, built for LAN/WireGuard networks.
 *
 * What this host plugin does:
 *  1. Wraps every registered HTTP route, every WebSocket upgrade and the SPA
 *     fallback in a session-cookie gate (structure studied in
 *     @xgone/dsh-remote, MIT — the wrapping/disposal pattern here is its own
 *     implementation of the same idea).
 *  2. After a gate login, MINTS the core's own Host-bound `dsh-auth-*`
 *     browser cookie (signed with client-connection's persisted secret read
 *     from the `client-connection/browser-session` credential record) so
 *     /api, the stream WebSocket and the SPA authenticate without any device
 *     ever seeing the launch token. Wire format mirrors core browser-auth v1
 *     (same as documented by xgone/dsh-remote issue #10).
 *  3. Runs a `/mini` pairing plane: an admin generates a short-lived QR
 *     grant, a phone scans it once, and the device receives a long-lived
 *     device cookie that the gate accepts — full GUI, no token, no second
 *     server, no reverse proxy. Roster + revocation in the admin page.
 *
 * Security posture:
 *  - scrypt-hashed passwords (N=16384,r=8,p=1) in a 0600 JSON store.
 *  - Fixed-window login rate limiting per IP+username; timing-safe compares.
 *  - Optional TOTP MFA (RFC 6238) + single-use backup codes.
 *  - First-admin bootstrap: loopback/bind-address only, or the `bootstrap`
 *    config block for headless servers.
 *  - Escape hatch: `enabled: false` in the patch restores the core's own
 *    token auth unchanged.
 *
 * NOT included (see README roadmap): fine-grained per-role RPC gating,
 * a dedicated mobile 3-view UI, PWA/ServiceWorker (needs HTTPS), gzip
 * tuning. Every device cookie gets admin-equivalent access BY DESIGN — this
 * plugin protects a private network, it is not an internet-edge hardening
 * layer.
 */
import z from "@deepseek-ai/schemastery";
import { randomBytes, randomUUID, createHmac, timingSafeEqual } from "node:crypto";
import { join } from "node:path";
import { dshHomePath } from "@deepseek-ai/dsh-home-paths";
import QRCode from "qrcode";
import { AccountStore, defaultStorePath, verifyPassword } from "./store.js";
import { generateBackupCodes, generateTotpSecret, hashBackupCode, otpauthUri, verifyTotp } from "./totp.js";
import {
  BROWSER_SESSION_RECORD_KEY,
  canonicalAuthority,
  cookieHeaderSet,
  cookieValueOf,
  decodeDshAuthCookie,
  decodeGateSessionCookie,
  dshAuthCookieName,
  encodeDshAuthCookie,
  encodeGateSessionCookie,
  readBrowserAuthSecret,
} from "./auth-cookie.js";
import { classify, createRateLimiter, isLoopbackSocket, readJsonBody } from "./gate.js";
import { renderAdminPage, renderLoginPage } from "./login-page.js";

const name = "homegate";
const inject = ["webServer", "credentials"];

const Config = z.object({
  enabled: z.boolean().default(true),
  session: z.object({
    cookieName: z.string().default("hg_session"),
    ttlSeconds: z.natural().min(60).max(60 * 60 * 24 * 30).default(2592000),
    secure: z.boolean().default(false),
  }).default({}),
  rateLimit: z.object({
    maxAttempts: z.natural().min(1).default(8),
    windowMs: z.natural().min(1000).default(900000),
  }).default({}),
  browserAuth: z.object({
    enabled: z.boolean().default(true),
  }).default({}),
  mini: z.object({
    enabled: z.boolean().default(true),
    grantTtlMs: z.natural().min(1000).default(300000),
    maxDevices: z.natural().min(1).default(10),
    deviceTtlDays: z.natural().min(1).default(90),
  }).default({}),
  // Optional headless bootstrap: provisions the first admin from config.
  // Remove the plaintext password after first login.
  bootstrap: z.object({
    username: z.string().min(1),
    password: z.string().min(1),
  }),
});

const GATED = Symbol.for("deepseek-homegate/gated");

/**
 * @param {import("@deepseek-ai/cordis").Context} ctx
 * @param {z.infer<typeof Config>} config
 */
function apply(ctx, config) {
  const cfg = config;
  const webServer = ctx.webServer;
  /* 셸이 TLS로 서비스하면 코어는 `https://` 오리진을 authority로 쓴다
     (dsh-client-connection: `requestAudience(headers, webServer.protocol === 'https:')`).
     같은 기준으로 발행해야 코어가 쿠키 이름을 찾는다. */
  const secureScheme = webServer?.protocol === "https:";
  const store = new AccountStore(defaultStorePath(dshHomePath()));
  const limiter = createRateLimiter(cfg.rateLimit);

  // ── headless bootstrap (config-declared first admin) ─────────────────────
  if (cfg.bootstrap?.username && cfg.bootstrap?.password) {
    if (store.ready) {
      ctx.logger.warn("[homegate] bootstrap config ignored — accounts already exist; remove the credentials from cordis.patch.yml");
    } else {
      const result = store.create(cfg.bootstrap.username.trim(), cfg.bootstrap.password, "admin", { allowFirst: true });
      if (result.error) throw new Error(`homegate: bootstrap account rejected (${result.error})`);
      ctx.logger.info(`[homegate] bootstrapped first admin "${result.account.username}" from config — remove the plaintext password after first login`);
    }
  }

  // ── core browser-cookie minting ───────────────────────────────────────────
  // Hard dependency: the credentials provider is present before this plugin
  // activates. Cordis 4.1 no longer reliably runs the old dynamic ctx.inject
  // callback here, which left core-cookie minting silently disabled and broke
  // every new device paired after a restart.
  const credentialsProvider = ctx.credentials ?? null;
  if (credentialsProvider === null) {
    ctx.logger.warn("[homegate] credentials service unavailable — core-cookie minting disabled; core token auth still applies on top");
  }
  let secretCache = null;
  let lastMissAt = 0;
  const coreSecret = async () => {
    if (!cfg.browserAuth.enabled || credentialsProvider === null) return null;
    const now = Date.now();
    if (secretCache && now - secretCache.at < 30000) return secretCache.value;
    if (now - lastMissAt < 300000) return null;
    try {
      const value = readBrowserAuthSecret(await credentialsProvider.readRecord(BROWSER_SESSION_RECORD_KEY));
      if (value) { secretCache = { value, at: now }; return value; }
    } catch { /* never break the request path */ }
    lastMissAt = now;
    return null;
  };
  /**
   * Ensure the request carries a live core browser cookie; mint one for the
   * authority the core will see (the request's own Host — no normalization,
   * this plugin binds LAN/WG addresses directly) and inject it so THIS
   * request authenticates immediately, plus Set-Cookie so the jar keeps it.
   */
  const ensureCoreCookie = async (req, res) => {
    if (!cfg.browserAuth.enabled || res.headersSent) return;
    const authority = canonicalAuthority(req.headers.host, secureScheme);
    if (authority === null) return;
    const secret = await coreSecret();
    if (secret === null) return;
    const existing = cookieValueOf(req.headers.cookie, dshAuthCookieName(authority));
    if (existing && decodeDshAuthCookie(existing, secret, authority)) return;
    const minted = encodeDshAuthCookie(authority, secret, cfg.session.ttlSeconds * 1000);
    if (typeof res.appendHeader !== "function") return;
    res.appendHeader("Set-Cookie", minted.cookie);
    req.headers.cookie = cookieHeaderSet(req.headers.cookie, minted.name, minted.value);
  };

  // ── identity ──────────────────────────────────────────────────────────────
  /** @returns {{type:'session'|'device', username:string, role:string}|null} */
  const authenticate = (req) => {
    const payload = decodeGateSessionCookie(cfg.session.cookieName, store.secret(), req.headers.cookie);
    if (payload) {
      if (payload.u.startsWith("device:")) {
        const device = store.getDevice(payload.u.slice(7));
        return device ? { type: "device", username: `device:${device.name}`, role: "user" } : null;
      }
      const account = store.get(payload.u);
      return account ? { type: "session", username: account.username, role: account.role } : null;
    }
    const device = authenticateDevice(req);
    return device ? { type: "device", username: `device:${device.name}`, role: "user" } : null;
  };

  // Device cookie: `hg_device=<id>.<hmac>` — revoked instantly by roster removal.
  const DEVICE_COOKIE = "hg_device";
  const deviceSig = (id) => createHmac("sha256", store.secret()).update(id).digest("base64url").slice(0, 16);
  const authenticateDevice = (req) => {
    const raw = cookieValueOf(req.headers.cookie, DEVICE_COOKIE);
    if (!raw) return null;
    const dot = raw.lastIndexOf(".");
    if (dot <= 0) return null;
    const id = raw.slice(0, dot);
    const given = Buffer.from(raw.slice(dot + 1));
    const expected = Buffer.from(deviceSig(id));
    if (given.length !== expected.length || !timingSafeEqual(given, expected)) return null;
    const device = store.getDevice(id);
    if (!device) return null;
    const maxAgeMs = cfg.mini.deviceTtlDays * 24 * 60 * 60 * 1000;
    if (Date.now() - device.createdAt > maxAgeMs) return null;
    store.touchDevice(id);
    return device;
  };
  const deviceCookieHeader = (id) => {
    const maxAge = cfg.mini.deviceTtlDays * 24 * 60 * 60;
    const secureAttr = cfg.session.secure ? "; Secure" : "";
    return `${DEVICE_COOKIE}=${id}.${deviceSig(id)}; Max-Age=${maxAge}; Path=/; Expires=${new Date(Date.now() + maxAge * 1000).toUTCString()}${secureAttr}; HttpOnly; SameSite=Lax`;
  };

  // ── MFA challenges (password OK, TOTP pending) ────────────────────────────
  /** @type {Map<string,{exp:number}>} */
  const challenges = new Map();

  // ── mini pairing grants (admin invites → phone scans once) ───────────────
  /** @type {Map<string,{exp:number}>} */
  const grants = new Map();

  // ── response helpers ──────────────────────────────────────────────────────
  const json = (res, status, body, headers = {}) => {
    res.writeHead(status, { "content-type": "application/json; charset=utf-8", "cache-control": "no-store", ...headers });
    res.end(JSON.stringify(body));
  };
  const html = (res, status, body, headers = {}) => {
    res.writeHead(status, { "content-type": "text/html; charset=utf-8", "cache-control": "no-store", ...headers });
    res.end(body);
  };
  const localeOf = (req) => (String(req.headers["accept-language"] ?? "").toLowerCase().startsWith("en") ? "en" : "ko");
  // Bootstrap (creating the first admin) is LOOPBACK-ONLY, like upstream. The
  // bind-address Host must NOT qualify: every LAN/WG client presents it as
  // their Host header, which would let any network peer claim the first admin
  // while the store is empty. A headless server bound to a LAN address uses
  // the `bootstrap` config block instead.
  //
  // A reverse proxy (nginx/caddy on the same host) also connects from 127.0.0.1,
  // so the socket test alone would let any remote client claim the first admin.
  // A forwarded request carries `x-forwarded-*`; those never bootstrap.
  const isBootstrapSocket = (req) =>
    isLoopbackSocket(req.socket)
    && req.headers["x-forwarded-for"] === undefined
    && req.headers["x-real-ip"] === undefined
    && req.headers.forwarded === undefined;
  const setLoginCookies = async (req, res, account) => {
    const headers = { "set-cookie": [encodeGateSessionCookie(cfg.session.cookieName, store.secret(), account, cfg.session.ttlSeconds * 1000, { secure: cfg.session.secure }).cookie] };
    const authority = canonicalAuthority(req.headers.host, secureScheme);
    const secret = await coreSecret();
    if (authority !== null && secret !== null) headers["set-cookie"].push(encodeDshAuthCookie(authority, secret, cfg.session.ttlSeconds * 1000).cookie);
    return headers;
  };

  // ── /auth/* plane (registered unwrapped; does its own checks) ─────────────
  const handleLogin = async (req, res) => {
    if (req.method === "GET") return html(res, 200, renderLoginPage({ locale: localeOf(req), bootstrap: !store.ready && isBootstrapSocket(req) }));
    if (req.method !== "POST") return json(res, 405, { error: "method-not-allowed" });
    const body = await readJsonBody(req);
    if (!body?.username || !body?.password) return json(res, 400, { error: "bad-request" });
    const key = `${req.socket?.remoteAddress ?? "?"}|${body.username}`;
    if (!limiter.check(key)) return json(res, 429, { error: "rate-limited", retryAfterMs: limiter.retryAfterMs(key) });
    const account = store.get(body.username);
    if (!account || !verifyPassword(body.password, account.hash)) {
      limiter.noteFailure(key);
      return json(res, 401, { error: "bad-credentials" });
    }
    limiter.reset(key);
    if (account.totp) {
      challenges.set(account.username, { exp: Date.now() + 300000 });
      return json(res, 200, { mfaRequired: true });
    }
    json(res, 200, { ok: true }, await setLoginCookies(req, res, account));
  };
  const handleMfaLogin = async (req, res) => {
    if (req.method !== "POST") return json(res, 405, { error: "method-not-allowed" });
    const body = await readJsonBody(req);
    const challenge = challenges.get(body?.username);
    if (!challenge || challenge.exp < Date.now()) return json(res, 401, { error: "no-challenge" });
    const account = store.get(body.username);
    if (!account) return json(res, 401, { error: "bad-credentials" });
    /* 제한 키에 접속 IP를 넣는다. 사용자명만 쓰면 제3자가 남의 MFA를 잠글 수 있다. */
    const key = `mfa|${req.socket?.remoteAddress ?? "?"}|${String(body.username)}`;
    if (!limiter.check(key)) return json(res, 429, { error: "rate-limited" });
    const code = String(body.code ?? "").trim();
    const valid = (account.totp && verifyTotp(account.totp.secret, code).valid) || store.useBackupCode(account.username, code, (c) => hashBackupCode(c, store.secret()));
    if (!valid) { limiter.noteFailure(key); return json(res, 401, { error: "bad-code" }); }
    challenges.delete(account.username);
    limiter.reset(key);
    json(res, 200, { ok: true }, await setLoginCookies(req, res, account));
  };

  const handleBootstrap = async (req, res) => {
    if (req.method !== "POST") return json(res, 405, { error: "method-not-allowed" });
    if (store.ready) return json(res, 409, { error: "already-initialized" });
    if (!isBootstrapSocket(req)) return json(res, 403, { error: "loopback-only" });
    const body = await readJsonBody(req);
    const result = store.create(String(body?.username ?? ""), String(body?.password ?? ""), "admin", { allowFirst: true });
    if (result.error) return json(res, 400, { error: result.error });
    json(res, 200, { ok: true }, await setLoginCookies(req, res, store.get(result.account.username)));
  };

  const handleLogout = (req, res) => {
    /* 게이트 세션 쿠키만 지우면 QR로 페어링한 기기(hg_device)와 30일짜리 코어 쿠키가
       남아 "로그아웃했는데 그대로 로그인" 상태가 된다. 셋 다 만료시킨다. */
    const secureAttr = cfg.session.secure ? "; Secure" : "";
    const cleared = [
      `${cfg.session.cookieName}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${secureAttr}`,
      `${DEVICE_COOKIE}=; Max-Age=0; Path=/; HttpOnly; SameSite=Lax${secureAttr}`,
    ];
    const authority = canonicalAuthority(req.headers.host, secureScheme);
    if (authority !== null) {
      cleared.push(`${dshAuthCookieName(authority)}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict${secureAttr}`);
    }
    json(res, 200, { ok: true }, { "set-cookie": cleared });
  };

  const handleMe = (req, res) => {
    const who = authenticate(req);
    if (!who) return json(res, 401, { error: "unauthenticated" });
    json(res, 200, { username: who.username, role: who.role, type: who.type });
  };

  const requireAdmin = (req, res) => {
    const who = authenticate(req);
    if (!who) { json(res, 401, { error: "unauthenticated" }); return null; }
    if (who.role !== "admin") { json(res, 403, { error: "admin-only" }); return null; }
    return who;
  };

  const handleAccounts = async (req, res) => {
    if (req.method === "GET") {
      if (requireAdmin(req, res) === null) return;
      return json(res, 200, { accounts: store.list() });
    }
    if (req.method !== "POST") return json(res, 405, { error: "method-not-allowed" });
    if (requireAdmin(req, res) === null) return;
    const body = await readJsonBody(req);
    if (!body?.op) return json(res, 400, { error: "bad-request" });
    if (body.op === "create") {
      /* 누락 필드를 그대로 넘기면 이름이 "undefined"인 관리자 계정이 만들어진다. */
      const username = String(body.username ?? "").trim();
      const password = String(body.password ?? "");
      if (username === "" || password === "") return json(res, 400, { error: "missing-credentials" });
      return json(res, 200, store.create(username, password, String(body.role ?? "user")) ?? {});
    }
    if (body.op === "remove") return json(res, 200, { removed: store.remove(String(body.username)) });
    if (body.op === "password") return json(res, 200, { updated: store.setPassword(String(body.username), String(body.password)) });
    if (body.op === "role") return json(res, 200, { updated: store.setRole(String(body.username), String(body.role)) });
    if (body.op === "mfa-disable") return json(res, 200, { updated: store.disableTotp(String(body.username)) });
    return json(res, 400, { error: "unknown-op" });
  };

  // Self-service MFA (any authenticated identity, stored against own account)
  const handleMfa = async (req, res) => {
    const who = authenticate(req);
    if (!who) return json(res, 401, { error: "unauthenticated" });
    if (who.type !== "session") return json(res, 403, { error: "account-only" });
    const account = store.get(who.username);
    if (req.method === "GET") {
      const secret = generateTotpSecret();
      const uri = otpauthUri({ secret, account: account.username });
      return json(res, 200, { secret, uri, qrDataUrl: await QRCode.toDataURL(uri) });
    }
    const body = await readJsonBody(req);
    if (req.method === "POST" && body?.op === "enable") {
      // The secret round-trips from the GET step; verify the code before storing.
      const pending = String(body.secret ?? "");
      if (!pending || !verifyTotp(pending, String(body.code ?? "")).valid) return json(res, 400, { error: "bad-code" });
      const codes = generateBackupCodes();
      store.setTotp(who.username, String(pending), codes.map((c) => hashBackupCode(c, store.secret())));
      return json(res, 200, { ok: true, backupCodes: codes });
    }
    if (req.method === "POST" && body?.op === "disable") return json(res, 200, { updated: store.disableTotp(who.username) });
    return json(res, 400, { error: "bad-request" });
  };

  const handleAdminPage = (req, res) => {
    const who = authenticate(req);
    if (!who) return html(res, 200, renderLoginPage({ locale: localeOf(req), bootstrap: false }));
    if (who.role !== "admin") return html(res, 403, `<main><h1>403</h1></main>`);
    html(res, 200, renderAdminPage({ locale: localeOf(req) }));
  };

  // ── /mini/* plane ─────────────────────────────────────────────────────────
  const handleInvite = async (req, res) => {
    if (requireAdmin(req, res) === null) return;
    if (!cfg.mini.enabled) return json(res, 404, { error: "mini-disabled" });
    if (store.listDevices().length >= cfg.mini.maxDevices) return json(res, 409, { error: "device-capacity" });
    const token = randomBytes(24).toString("base64url");
    grants.set(token, { exp: Date.now() + cfg.mini.grantTtlMs });
    for (const [key, entry] of grants) if (entry.exp < Date.now()) grants.delete(key);
    const scheme = secureScheme ? "https" : "http";
    const url = `${scheme}://${canonicalAuthority(req.headers.host, secureScheme) ?? "127.0.0.1"}/mini/p?g=${token}`;
    json(res, 200, { url, qrDataUrl: await QRCode.toDataURL(url) });
  };

  const handlePair = (req, res) => {
    if (!cfg.mini.enabled) return json(res, 404, { error: "mini-disabled" });
    const token = new URL(req.url ?? "/", "http://x").searchParams.get("g");
    const entry = token ? grants.get(token) : null;
    if (!entry || entry.exp < Date.now()) return html(res, 400, "<main><h1>링크가 만료되었습니다</h1><p class=sub>PC에서 페어링 QR을 새로 생성하세요.</p></main>");
    grants.delete(token);
    const ua = String(req.headers["user-agent"] ?? "");
    const nameGuess = /iPhone|iPad/.test(ua) ? "iPhone" : /Android/.test(ua) ? "Android" : /Mac/.test(ua) ? "Mac" : /Windows/.test(ua) ? "Windows" : "device";
    const device = store.addDevice(randomBytes(6).toString("base64url").slice(0, 8), nameGuess);
    res.writeHead(302, { location: "/", "set-cookie": deviceCookieHeader(device.id), "cache-control": "no-store" });
    res.end();
  };

  const handleDevices = async (req, res) => {
    if (req.method === "GET") {
      if (requireAdmin(req, res) === null) return;
      return json(res, 200, { devices: store.listDevices() });
    }
    if (req.method !== "POST") return json(res, 405, { error: "method-not-allowed" });
    if (requireAdmin(req, res) === null) return;
    const body = await readJsonBody(req);
    if (body?.op === "remove") return json(res, 200, { removed: store.removeDevice(String(body.id)) });
    return json(res, 400, { error: "bad-request" });
  };

  // ── gate wrapping ─────────────────────────────────────────────────────────
  const originalRegister = webServer.register.bind(webServer);
  const originalRegisterUpgrade = webServer.registerUpgrade.bind(webServer);
  const originalRegisterFallback = webServer.registerFallback.bind(webServer);
  const wrappedOriginals = new WeakMap();
  const unwrap = (handler) => wrappedOriginals.get(handler) ?? handler;

  const gate = (req) => {
    const who = authenticate(req);
    const pathname = (() => { try { return new URL(req.url ?? "/", "http://x").pathname; } catch { return "/"; } })();
    const decision = classify({ pathname, hasGateSession: who !== null });
    return { who, decision };
  };

  const wrapHttp = (handler) => {
    if (typeof handler !== "function" || handler[GATED]) return handler;
    const gated = async (req, res, ...rest) => {
      const { who, decision } = gate(req);
      if (decision.action === "pass") {
        await ensureCoreCookie(req, res);
        return handler(req, res, ...rest);
      }
      if (decision.action === "public") return handler(req, res, ...rest);
      if (String(req.headers.accept ?? "").includes("text/html") && req.method === "GET") {
        return html(res, 401, renderLoginPage({ locale: localeOf(req), bootstrap: !store.ready && isBootstrapSocket(req) }));
      }
      return json(res, 401, { error: "unauthenticated" });
    };
    gated[GATED] = true;
    wrappedOriginals.set(gated, handler);
    return gated;
  };

  const wrapUpgrade = (handler) => {
    if (typeof handler !== "function" || handler[GATED]) return handler;
    const gated = (req, socket, head) => {
      const { who } = gate(req);
      if (who === null) {
        socket.write("HTTP/1.1 401 Unauthorized\r\nconnection: close\r\n\r\n");
        socket.destroy();
        return;
      }
      // The core authorizes the WS by its own cookie; inject a live one.
      const authority = canonicalAuthority(req.headers.host, secureScheme);
      void (async () => {
        const secret = await coreSecret();
        if (authority !== null && secret !== null) {
          const existing = cookieValueOf(req.headers.cookie, dshAuthCookieName(authority));
          if (!existing || !decodeDshAuthCookie(existing, secret, authority)) {
            const minted = encodeDshAuthCookie(authority, secret, cfg.session.ttlSeconds * 1000);
            req.headers.cookie = cookieHeaderSet(req.headers.cookie, minted.name, minted.value);
          }
        }
        handler(req, socket, head);
      })().catch(() => socket.destroy());
    };
    gated[GATED] = true;
    wrappedOriginals.set(gated, handler);
    return gated;
  };

  const wrapFallbackResource = (resource) => async (request, peer) => {
    const headers = Object.fromEntries([...request.headers].map(([key, value]) => [key.toLowerCase(), value]));
    const fakeReq = { headers, url: request.url, method: request.method };
    const { who } = gate(fakeReq);
    if (who === null) {
      const body = renderLoginPage({ locale: localeOf(fakeReq), bootstrap: !store.ready && false });
      return new Response(body, {
        status: 401,
        headers: { "content-type": "text/html; charset=utf-8", "cache-control": "no-store" },
      });
    }
    const authority = canonicalAuthority(headers.host, secureScheme);
    const secret = authority !== null ? await coreSecret() : null;
    let requestToPass = request;
    let minted = null;
    if (authority !== null && secret !== null) {
      const cookieHeader = headers.cookie ?? "";
      const existing = cookieValueOf(cookieHeader, dshAuthCookieName(authority));
      if (!existing || !decodeDshAuthCookie(existing, secret, authority)) {
        minted = encodeDshAuthCookie(authority, secret, cfg.session.ttlSeconds * 1000);
        const nextHeaders = new Headers(request.headers);
        nextHeaders.set("cookie", cookieHeaderSet(cookieHeader, minted.name, minted.value));
        requestToPass = new Request(request, { headers: nextHeaders });
      }
    }
    const response = await resource(requestToPass, peer);
    if (minted === null) return response;
    const outHeaders = new Headers(response.headers);
    outHeaders.append("set-cookie", minted.cookie);
    return new Response(response.body, { status: response.status, statusText: response.statusText, headers: outHeaders });
  };

  const wrapFallback = (handler) => {
    if (handler !== null && typeof handler === "object" && typeof handler.resource === "function") {
      return { resource: wrapFallbackResource(handler.resource) };
    }
    if (typeof handler !== "function" || handler[GATED]) return handler;
    const gated = async (req, res) => {
      const { who } = gate(req);
      if (who === null) {
        return html(res, 401, renderLoginPage({ locale: localeOf(req), bootstrap: !store.ready && isBootstrapSocket(req) }));
      }
      await ensureCoreCookie(req, res);
      return handler(req, res);
    };
    gated[GATED] = true;
    wrappedOriginals.set(gated, handler);
    return gated;
  };

  const disposers = [];
  if (cfg.enabled) {
    disposers.push(originalRegister({ kind: "exact", path: "/auth/login", handler: handleLogin }));
    disposers.push(originalRegister({ kind: "exact", path: "/auth/mfa/login", handler: handleMfaLogin }));
    disposers.push(originalRegister({ kind: "exact", path: "/auth/bootstrap", handler: handleBootstrap }));
    disposers.push(originalRegister({ kind: "exact", path: "/auth/logout", handler: handleLogout }));
    disposers.push(originalRegister({ kind: "exact", path: "/auth/me", handler: handleMe }));
    disposers.push(originalRegister({ kind: "exact", path: "/auth/accounts", handler: handleAccounts }));
    disposers.push(originalRegister({ kind: "exact", path: "/auth/mfa", handler: handleMfa }));
    disposers.push(originalRegister({ kind: "exact", path: "/auth/admin", handler: handleAdminPage }));
    disposers.push(originalRegister({ kind: "exact", path: "/mini/invite", handler: handleInvite }));
    disposers.push(originalRegister({ kind: "exact", path: "/mini/p", handler: handlePair }));
    disposers.push(originalRegister({ kind: "exact", path: "/mini/devices", handler: handleDevices }));

    // Wrap everything already registered, then everything registered later.
    // These are `private` fields of dsh-host-webserver (see its .d.ts): if a
    // harness upgrade renames or hides them, fail LOUDLY here instead of
    // silently leaving the gate half-installed.
    try {
      for (const route of webServer.exact.values()) route.handler = wrapHttp(route.handler);
      for (const route of webServer.prefixes.values()) route.handler = wrapHttp(route.handler);
      for (const route of webServer.upgrades.values()) route.handler = wrapUpgrade(route.handler);
      if (webServer.fallback !== undefined) webServer.fallback = wrapFallback(webServer.fallback);
      webServer.register = (route) => originalRegister({ ...route, handler: wrapHttp(route.handler) });
      webServer.registerUpgrade = (route) => originalRegisterUpgrade({ ...route, handler: wrapUpgrade(route.handler) });
      webServer.registerFallback = (handler) => {
        return originalRegisterFallback(wrapFallback(handler));
      };
    } catch (error) {
      ctx.logger.error(
        `[homegate] 게이트 설치 실패 — dsh-host-webserver 내부 구조가 바뀐 것으로 보입니다. ` +
        `이 실행에서는 잠금이 일부만 적용됩니다: ${String(error)}`,
      );
    }
  }

  ctx.effect(() => () => {
    for (const dispose of disposers) dispose();
    if (cfg.enabled) {
      webServer.register = originalRegister;
      webServer.registerUpgrade = originalRegisterUpgrade;
      webServer.registerFallback = originalRegisterFallback;
      for (const route of webServer.exact.values()) route.handler = unwrap(route.handler);
      for (const route of webServer.prefixes.values()) route.handler = unwrap(route.handler);
      for (const route of webServer.upgrades.values()) route.handler = unwrap(route.handler);
      if (webServer.fallback !== undefined) webServer.fallback = unwrap(webServer.fallback);
    }
  }, "deepseek-homegate: gate");

  ctx.logger.info(
    `[homegate] authentication ${cfg.enabled ? "enabled" : "DISABLED (escape hatch)"} — ` +
    `${store.list().length} account(s), ${store.listDevices().length} device(s), store at ${store.path}`,
  );
}

export default { name, inject, Config, apply };
export { Config, apply, inject, name };
