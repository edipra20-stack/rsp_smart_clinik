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
      "Content-Type, Authorization",
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

/*
 * BUILD 78C
 * Server-side one-time Admin bootstrap.
 *
 * Username/password TIDAK berasal dari browser.
 * Keduanya diambil dari Cloudflare Secrets:
 *
 * ADMIN_INITIAL_USER
 * ADMIN_INITIAL_PASSWORD
 *
 * Bootstrap hanya bekerja jika auth_config masih kosong.
 */
async function bootstrapAdmin(env) {
  if (!env.ADMIN_INITIAL_USER || !env.ADMIN_INITIAL_PASSWORD) {
    return {
      ok: false,
      reason: "INITIAL_ADMIN_SECRET_MISSING"
    };
  }

  const existing = await env.DB
    .prepare(
      "SELECT id FROM auth_config WHERE id = 1"
    )
    .first();

  if (existing) {
    return {
      ok: true,
      initialized: true,
      created: false
    };
  }

  const username =
    String(env.ADMIN_INITIAL_USER).trim();

  const password =
    String(env.ADMIN_INITIAL_PASSWORD);

  if (!username || !password) {
    return {
      ok: false,
      reason: "INITIAL_ADMIN_SECRET_EMPTY"
    };
  }

  if (password.length < 8) {
    return {
      ok: false,
      reason: "INITIAL_ADMIN_PASSWORD_TOO_SHORT"
    };
  }

  const salt = secureRandomBytes(16);

  const passwordHash =
    await pbkdf2(password, salt);

  /*
   * INSERT OR IGNORE digunakan untuk mencegah
   * dua request pertama membuat dua akun
   * apabila datang hampir bersamaan.
   */
  await env.DB
    .prepare(`
      INSERT OR IGNORE INTO auth_config
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

  const created = await env.DB
    .prepare(
      "SELECT id FROM auth_config WHERE id = 1"
    )
    .first();

  return {
    ok: !!created,
    initialized: !!created,
    created: !!created
  };
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

  if (
    !constantTimeEqualText(
      String(username),
      String(row.username)
    )
  ) {
    return {
      ok: false,
      reason: "INVALID_CREDENTIALS"
    };
  }

  const salt = new Uint8Array(row.salt);
  const storedHash =
    new Uint8Array(row.password_hash);

  const calculatedHash =
    await pbkdf2(
      String(password),
      salt
    );

  if (!equalBytes(
    calculatedHash,
    storedHash
  )) {
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

  const username =
    String(body.username || "").trim();

  const password =
    String(body.password || "");

  if (!username || !password) {
    return json({
      ok: false,
      error: "Username dan password wajib diisi."
    }, 400);
  }

  const result =
    await verifyPassword(
      username,
      password,
      env
    );

  if (!result.ok) {
    if (
      result.reason ===
      "AUTH_NOT_INITIALIZED"
    ) {
      return json({
        ok: false,
        error:
          "Login online belum diinisialisasi."
      }, 503);
    }

    return json({
      ok: false,
      error:
        "Username atau password salah."
    }, 401);
  }

  return json({
    ok: true,
    build: "78C",
    username: result.username,
    message: "Login berhasil."
  });
}function adminBootstrapPage() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>RSP SMART CLINIC - Admin Bootstrap</title>
  <style>
    body {
      font-family: Arial, sans-serif;
      background: #f4f6f8;
      margin: 0;
      padding: 40px 20px;
    }

    .box {
      max-width: 480px;
      margin: auto;
      background: white;
      padding: 30px;
      border-radius: 12px;
      box-shadow: 0 4px 20px rgba(0,0,0,.08);
    }

    h1 {
      margin-top: 0;
      font-size: 22px;
    }

    p {
      color: #555;
      line-height: 1.5;
    }

    button {
      width: 100%;
      padding: 13px;
      border: 0;
      border-radius: 8px;
      background: #2563eb;
      color: white;
      font-size: 16px;
      cursor: pointer;
    }

    button:disabled {
      opacity: .6;
      cursor: not-allowed;
    }

    #result {
      margin-top: 20px;
      padding: 12px;
      border-radius: 8px;
      display: none;
      white-space: pre-wrap;
    }

    .ok {
      background: #dcfce7;
      color: #166534;
    }

    .error {
      background: #fee2e2;
      color: #991b1b;
    }
  </style>
</head>

<body>
  <div class="box">
    <h1>RSP SMART CLINIC</h1>

    <p>
      Inisialisasi Admin Online satu kali.
      Username dan password diambil langsung
      dari Cloudflare Secret.
    </p>

    <p>
      Password tidak ditampilkan dan tidak
      dikirim dari halaman ini.
    </p>

    <button id="btn" onclick="bootstrap()">
      Buat Admin Online
    </button>

    <div id="result"></div>
  </div>

<script>
async function bootstrap() {
  const btn = document.getElementById("btn");
  const result = document.getElementById("result");

  btn.disabled = true;
  btn.textContent = "Memproses...";

  result.style.display = "block";
  result.className = "";
  result.textContent = "Menginisialisasi Admin Online...";

  try {
    const response = await fetch("/api/admin/bootstrap", {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: "{}"
    });

    const data = await response.json();

    if (data.ok) {
      result.className = "ok";

      if (data.created) {
        result.textContent =
          "Admin Online berhasil dibuat.\\n\\n" +
          "Silakan lanjutkan ke halaman login.";
      } else {
        result.textContent =
          "Admin Online sudah tersedia.\\n\\n" +
          "Bootstrap tidak melakukan perubahan.";
      }

      btn.textContent = "Selesai";
      return;
    }

    result.className = "error";
    result.textContent =
      data.error || "Bootstrap gagal.";

    btn.disabled = false;
    btn.textContent = "Coba Lagi";

  } catch (error) {
    result.className = "error";
    result.textContent =
      "Tidak dapat terhubung ke server.\\n\\n" +
      String(error);

    btn.disabled = false;
    btn.textContent = "Coba Lagi";
  }
}
</script>

</body>
</html>`;
}
function adminBootstrapPage() {
  return `<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>RSP SMART CLINIC - Admin Setup</title>

<style>
body {
  font-family: Arial, sans-serif;
  background: #f4f6f8;
  margin: 0;
  padding: 40px 20px;
}

.box {
  max-width: 460px;
  margin: auto;
  background: #fff;
  padding: 30px;
  border-radius: 12px;
  box-shadow: 0 4px 20px rgba(0,0,0,.08);
}

h1 {
  margin-top: 0;
  font-size: 22px;
}

label {
  display: block;
  margin-top: 18px;
  margin-bottom: 6px;
  font-weight: bold;
}

input {
  box-sizing: border-box;
  width: 100%;
  padding: 12px;
  border: 1px solid #ccc;
  border-radius: 7px;
  font-size: 15px;
}

button {
  width: 100%;
  margin-top: 22px;
  padding: 13px;
  border: 0;
  border-radius: 8px;
  background: #2563eb;
  color: white;
  font-size: 16px;
  cursor: pointer;
}

button:disabled {
  opacity: .6;
  cursor: not-allowed;
}

#result {
  display: none;
  margin-top: 20px;
  padding: 12px;
  border-radius: 8px;
  white-space: pre-wrap;
}

.ok {
  background: #dcfce7;
  color: #166534;
}

.error {
  background: #fee2e2;
  color: #991b1b;
}
</style>
</head>

<body>

<div class="box">

<h1>RSP SMART CLINIC</h1>

<p>
Inisialisasi Admin Online satu kali.
</p>

<label for="token">
Token Setup
</label>

<input
  id="token"
  type="password"
  autocomplete="off"
  placeholder="Masukkan ADMIN_SETUP_TOKEN"
>

<button id="btn" onclick="bootstrap()">
Buat Admin Online
</button>

<div id="result"></div>

</div>

<script>
async function bootstrap() {

  const token =
    document.getElementById("token").value.trim();

  const btn =
    document.getElementById("btn");

  const result =
    document.getElementById("result");

  if (!token) {
    result.style.display = "block";
    result.className = "error";
    result.textContent =
      "Token Setup wajib diisi.";
    return;
  }

  btn.disabled = true;
  btn.textContent = "Memproses...";

  result.style.display = "block";
  result.className = "";
  result.textContent =
    "Membuat Admin Online...";

  try {

    const response = await fetch(
      "/api/admin/bootstrap",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Admin-Setup-Token": token
        },
        body: "{}"
      }
    );

    const data =
      await response.json();

    if (data.ok) {

      result.className = "ok";

      if (data.created) {

        result.textContent =
          "Admin Online berhasil dibuat.\\n\\n" +
          "Sekarang Anda dapat menggunakan " +
          "username dan password baru untuk login.";

      } else {

        result.textContent =
          "Admin Online sudah tersedia.\\n\\n" +
          "Tidak ada perubahan dilakukan.";
      }

      document.getElementById("token").value = "";

      btn.textContent = "Selesai";
      return;
    }

    result.className = "error";
    result.textContent =
      data.error ||
      "Bootstrap gagal.";

    btn.disabled = false;
    btn.textContent = "Coba Lagi";

  } catch (error) {

    result.className = "error";

    result.textContent =
      "Tidak dapat terhubung ke server.\\n\\n" +
      String(error);

    btn.disabled = false;
    btn.textContent = "Coba Lagi";
  }
}
</script>

</body>
</html>`;
}
export default {
  async fetch(request, env) {
    const cors =
      getCorsHeaders(request);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: cors
      });
    }
  if (
  url.pathname === "/admin-bootstrap" &&
  request.method === "GET"
) {
  return new Response(
    adminBootstrapPage(),
    {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store"
      }
    }
  );
}

    const url =
      new URL(request.url);
if (
  url.pathname === "/admin-bootstrap" &&
  request.method === "GET"
) {
  return new Response(
    adminBootstrapPage(),
    {
      status: 200,
      headers: {
        "Content-Type": "text/html; charset=utf-8",
        "Cache-Control": "no-store"
      }
    }
  );
}
    try {

      /*
       * =================================================
       * HEALTH
       * =================================================
       */
      if (
        url.pathname === "/api/health" &&
        request.method === "GET"
      ) {
        const row =
          await env.DB
            .prepare(
              "SELECT COUNT(*) AS total FROM app_state"
            )
            .first();

        return json({
          ok: true,
          build: "78C",
          database: "connected",
          app_state_rows:
            Number(row.total || 0)
        }, 200, cors);
      }

      /*
       * =================================================
       * AUTH STATUS
       * =================================================
       */
      if (
        url.pathname === "/api/auth-status" &&
        request.method === "GET"
      ) {
        const row =
          await env.DB
            .prepare(
              "SELECT username FROM auth_config WHERE id = 1"
            )
            .first();

        return json({
          ok: true,
          initialized: !!row,
          username:
            row ? row.username : null
        }, 200, cors);
      }

      /*
       * =================================================
       * ONE-TIME SERVER-SIDE BOOTSTRAP
       *
       * Tidak menerima password.
       * Tidak menerima username.
       * Mengambil keduanya dari Cloudflare Secrets.
       *
       * Endpoint ini aman dipanggil berulang.
       * Setelah auth_config terisi, tidak ada akun
       * baru yang dibuat.
       * =================================================
       */
      if (
  url.pathname === "/api/admin/bootstrap" &&
  request.method === "POST"
) {
   const setupToken =
  request.headers.get("X-Admin-Setup-Token") || "";

if (!env.ADMIN_SETUP_TOKEN) {
  return json({
    ok: false,
    error:
      "ADMIN_SETUP_TOKEN belum dikonfigurasi."
  }, 500, cors);
}

if (
  !constantTimeEqualText(
    setupToken,
    env.ADMIN_SETUP_TOKEN
  )
) {
  return json({
    ok: false,
    error:
      "Token Setup tidak valid."
  }, 403, cors);
}
        ) {
        const result =
          await bootstrapAdmin(env);

        if (!result.ok) {
          if (
            result.reason ===
            "INITIAL_ADMIN_SECRET_MISSING"
          ) {
            return json({
              ok: false,
              error:
                "ADMIN_INITIAL_USER atau ADMIN_INITIAL_PASSWORD belum tersedia."
            }, 500, cors);
          }

          if (
            result.reason ===
            "INITIAL_ADMIN_PASSWORD_TOO_SHORT"
          ) {
            return json({
              ok: false,
              error:
                "ADMIN_INITIAL_PASSWORD minimal 8 karakter."
            }, 500, cors);
          }

          return json({
            ok: false,
            error:
              "Bootstrap Admin gagal."
          }, 500, cors);
        }

        return json({
          ok: true,
          build: "78C",
          initialized:
            result.initialized,
          created:
            result.created,
          message:
            result.created
              ? "Admin Online berhasil dibuat."
              : "Admin Online sudah tersedia."
        }, 200, cors);
      }

      /*
       * =================================================
       * LOGIN
       * =================================================
       */
      if (
        url.pathname === "/api/login" &&
        request.method === "POST"
      ) {
        return await handleLogin(
          request,
          env
        );
      }

      /*
       * =================================================
       * DB STATUS
       * =================================================
       */
      if (
        url.pathname === "/api/db-status" &&
        request.method === "GET"
      ) {
        const tables =
          await env.DB
            .prepare(`
              SELECT name
              FROM sqlite_master
              WHERE type = 'table'
              ORDER BY name
            `)
            .all();

        return json({
          ok: true,
          build: "78C",
          tables: tables.results
        }, 200, cors);
      }

      /*
       * =================================================
       * PUBLIC SETTINGS
       * =================================================
       */
      if (
        url.pathname === "/api/public-settings" &&
        request.method === "GET"
      ) {
        const row =
          await env.DB
            .prepare(
              "SELECT data FROM clinic_settings WHERE id = 1"
            )
            .first();

        let settings = {};

        if (
          row &&
          row.data
        ) {
          try {
            settings =
              JSON.parse(row.data);
          } catch {
            settings = {};
          }
        }

        return json({
          ok: true,
          clinicName:
            settings.clinicName ||
            "RSP SMART CLINIC",
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

      /*
       * =================================================
       * REGISTRATION COUNT
       * =================================================
       */
      if (
        url.pathname ===
          "/api/registration-count" &&
        request.method === "GET"
      ) {
        const row =
          await env.DB
            .prepare(
              "SELECT COUNT(*) AS total FROM registrations"
            )
            .first();

        return json({
          ok: true,
          total:
            Number(row.total || 0)
        }, 200, cors);
      }

      return json({
        ok: false,
        error:
          "Endpoint tidak ditemukan.",
        path:
          url.pathname
      }, 404, cors);

    } catch (error) {

      return json({
        ok: false,
        build: "78C",
        error:
          String(error)
      }, 500, cors);
    }
  }
};
