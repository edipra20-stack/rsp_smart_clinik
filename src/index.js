const ITERATIONS = 210000;
const KEY_LENGTH = 256;

function json(data, status = 200) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store"
    }
  });
}

function bytesToHex(buffer) {
  return Array.from(new Uint8Array(buffer))
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) {
    throw new Error("Invalid hex");
  }

  const bytes = new Uint8Array(hex.length / 2);

  for (let i = 0; i < bytes.length; i++) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }

  return bytes;
}

function equalBytes(a, b) {
  if (a.length !== b.length) return false;

  let result = 0;

  for (let i = 0; i < a.length; i++) {
    result |= a[i] ^ b[i];
  }

  return result === 0;
}

async function pbkdf2(password, salt) {
  const encoder = new TextEncoder();

  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
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

  if (String(username) !== String(row.username)) {
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

function getCorsHeaders(request) {
  const origin = request.headers.get("Origin") || "";

  const allowed = [
    "https://rsp-smart-clinik.com",
    "https://www.rsp-smart-clinik.com"
  ];

  const headers = {
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type, Authorization",
    "Access-Control-Max-Age": "86400",
    "Vary": "Origin"
  };

  if (allowed.includes(origin)) {
    headers["Access-Control-Allow-Origin"] = origin;
  }

  return headers;
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
    build: "78",
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
          .prepare("SELECT COUNT(*) AS total FROM app_state")
          .first();

        return new Response(
          JSON.stringify({
            ok: true,
            build: "78",
            database: "connected",
            app_state_rows: Number(row.total || 0)
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              ...cors
            }
          }
        );
      }

      if (
        url.pathname === "/api/login" &&
        request.method === "POST"
      ) {
        const response = await handleLogin(request, env);

        for (const [key, value] of Object.entries(cors)) {
          response.headers.set(key, value);
        }

        return response;
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

        return new Response(
          JSON.stringify({
            ok: true,
            initialized: !!row,
            username: row ? row.username : null
          }),
          {
            status: 200,
            headers: {
              "Content-Type": "application/json",
              ...cors
            }
          }
        );
      }

      return new Response(
        JSON.stringify({
          ok: false,
          error: "Endpoint tidak ditemukan."
        }),
        {
          status: 404,
          headers: {
            "Content-Type": "application/json",
            ...cors
          }
        }
      );

    } catch (error) {
      return new Response(
        JSON.stringify({
          ok: false,
          build: "78",
          error: String(error)
        }),
        {
          status: 500,
          headers: {
            "Content-Type": "application/json",
            ...cors
          }
        }
      );
    }
  }
};
