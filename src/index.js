const ITERATIONS = 210000;
const KEY_LENGTH = 256;

function json(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      ...extraHeaders
    }
  });
}

function getCorsHeaders(request) {
  const origin = request.headers.get("Origin") || "";

  const allowedOrigins = [
    "https://rsp-smart-clinik.edipra20.workers.dev"
  ];

  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, X-Admin-Setup-Token",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };

  if (allowedOrigins.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return headers;
}

async function pbkdf2(password, salt) {
  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    {
      name: "PBKDF2"
    },
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations: ITERATIONS,
      hash: "SHA-256"
    },
    key,
    KEY_LENGTH
  );

  return new Uint8Array(bits);
}

function secureRandomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function constantTimeEqualText(a, b) {
  if (typeof a !== "string" || typeof b !== "string") {
    return false;
  }

  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }

  return result === 0;
}

function equalBytes(a, b) {
  if (a.length !== b.length) {
    return false;
  }

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

async function verifyPassword(username, password, env) {
  const row = await env.DB
    .prepare(
      "SELECT username, salt, password_hash FROM auth_config WHERE id = 1"
    )
    .first();

  if (!row) {
    return {
      ok: false,
      reason: "AUTH_NOT_INITIALIZED"
    };
  }

  if (!constantTimeEqualText(String(username), String(row.username))) {
    return {
      ok: false,
      reason: "INVALID_CREDENTIALS"
    };
  }

  const salt = new Uint8Array(row.salt);
  const storedHash = new Uint8Array(row.password_hash);

  const calculatedHash = await pbkdf2(
    String(password),
    salt
  );

  if (!equalBytes(calculatedHash, storedHash)) {
    return {
      ok: false,
      reason: "INVALID_CREDENTIALS"
    };
  }

  return {
    ok: true,
    username: row.username
  };
}

async function handleInitializeAdmin(request, env) {
  const setupToken =
    request.headers.get("X-Admin-Setup-Token") || "";

  if (!env.ADMIN_SETUP_TOKEN) {
    return json({
      ok: false,
      error: "ADMIN_SETUP_TOKEN belum dikonfigurasi di Cloudflare."
    }, 500);
  }

  if (!constantTimeEqualText(
    setupToken,
    env.ADMIN_SETUP_TOKEN
  )) {
    return json({
      ok: false,
      error: "Token setup tidak valid."
    }, 403);
  }

  const existing = await env.DB
    .prepare(
      "SELECT id, username FROM auth_config WHERE id = 1"
    )
    .first();

  if (existing) {
    return json({
      ok: false,
      error: "Akun Admin Online sudah diinisialisasi.",
      username: existing.username
    }, 409);
  }

  let body;

  try {
    body = await request.json();
  } catch {
    return json({
      ok: false,
      error: "Data JSON tidak valid."
    }, 400);
  }

  const username = String(body.username || "").trim();
  const password = String(body.password || "");

  if (!username) {
    return json({
      ok: false,
      error: "Username wajib diisi."
    }, 400);
  }

  if (password.length < 8) {
    return json({
      ok: false,
      error: "Password minimal 8 karakter."
    }, 400);
  }

  const salt = secureRandomBytes(16);
  const passwordHash = await pbkdf2(password, salt);

  await env.DB
    .prepare(`
      INSERT INTO auth_config
      (
        id,
        username,
        salt,
        password_hash,
        changed_at
      )
      VALUES
      (
        1,
        ?,
        ?,
        ?,
        datetime('now')
      )
    `)
    .bind(
      username,
      salt,
      passwordHash
    )
    .run();

  return json({
    ok: true,
    build: "78B",
    message: "Admin Online berhasil dibuat.",
    username
  });
}

async function handleLogin(request, env) {
  let body;

  try {
    body = await request.json();
  } catch {
    return json({
      ok: false,
      error: "Format permintaan tidak valid."
    }, 400);
  }

  const username = String(body.username || "").trim();
  const password = String(body.password || "");

  if (!username || !password) {
    return json({
      ok: false,
      error: "Username dan password wajib diisi."
    }, 400);
  }

  const result = await verifyPassword(
    username,
    password,
    env
  );

  if (!result.ok) {
    if (result.reason === "AUTH_NOT_INITIALIZED") {
      return json({
        ok: false,
        error: "Login online belum diinisialisasi."
      }, 503);
    }

    return json({
      ok: false,
      error: "Username atau password salah."
    }, 401);
  }

  return json({
    ok: true,
    build: "78B",
    username: result.username,
    message: "Login berhasil."
  });
}

export default {
  async fetch(request, env) {
    const cors = getCorsHeaders(request);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: cors
      });
    }

    const url = new URL(request.url);

    try {
      if (
        url.pathname === "/api/health" &&
        request.method === "GET"
      ) {
        const row = await env.DB
          .prepare(
            "SELECT COUNT(*) AS total FROM app_state"
          )
          .first();

        return json({
          ok: true,
          build: "78B",
          database: "connected",
          app_state_rows: Number(row.total || 0)
        }, 200, cors);
      }

      if (
        url.pathname === "/api/auth-status" &&
        request.method === "GET"
      ) {
        const row = await env.DB
          .prepare(
            "SELECT username FROM auth_config WHERE id = 1"
          )
          .first();

        return json({
          ok: true,
          initialized: !!row,
          username: row ? row.username : null
        }, 200, cors);
      }

      if (
        url.pathname === "/api/admin/initialize" &&
        request.method === "POST"
      ) {
        return await handleInitializeAdmin(request, env);
      }

      if (
        url.pathname === "/api/login" &&
        request.method === "POST"
      ) {
        return await handleLogin(request, env);
      }

      if (
        url.pathname === "/api/db-status" &&
        request.method === "GET"
      ) {
        const tables = await env.DB
          .prepare(`
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            ORDER BY name
          `)
          .all();

        return json({
          ok: true,
          build: "78B",
          tables: tables.results
        }, 200, cors);
      }

      if (
        url.pathname === "/api/public-settings" &&
        request.method === "GET"
      ) {
        const row = await env.DB
          .prepare(
            "SELECT data FROM clinic_settings WHERE id = 1"
          )
          .first();

        let settings = {};

        if (row && row.data) {
          try {
            settings = JSON.parse(row.data);
          } catch {
            settings = {};
          }
        }

        return json({
          ok: true,
          clinicName:
            settings.clinicName || "RSP SMART CLINIC",
          tagline:
            settings.tagline || "",
          address:
            settings.address || "",
          phone:
            settings.phone || "",
          whatsapp:
            settings.whatsapp || "",
          publicBaseUrl:
            settings.publicBaseUrl || ""
        }, 200, cors);
      }

      if (
        url.pathname === "/api/registration-count" &&
        request.method === "GET"
      ) {
        const row = await env.DB
          .prepare(
            "SELECT COUNT(*) AS total FROM registrations"
          )
          .first();

        return json({
          ok: true,
          total: Number(row.total || 0)
        }, 200, cors);
      }

      return json({
        ok: false,
        error: "Endpoint tidak ditemukan.",
        path: url.pathname
      }, 404, cors);

    } catch (error) {
      return json({
        ok: false,
        build: "78B",
        error: String(error)
      }, 500, cors);
    }
  }
};
