export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    try {
      // Health check
      if (url.pathname === "/api/health") {
        const result = await env.DB
          .prepare("SELECT COUNT(*) AS total FROM app_state")
          .first();

        return Response.json({
          ok: true,
          build: "77",
          service: "RSP SMART CLINIC D1 API",
          database: "connected",
          app_state_rows: result.total
        });
      }

      // Database information
      if (url.pathname === "/api/db-status") {
        const tables = await env.DB
          .prepare(`
            SELECT name
            FROM sqlite_master
            WHERE type = 'table'
            ORDER BY name
          `)
          .all();

        return Response.json({
          ok: true,
          build: "77",
          tables: tables.results
        });
      }

      // Public clinic settings
      if (url.pathname === "/api/public-settings") {
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

        return Response.json({
          ok: true,
          clinicName: settings.clinicName || "RSP SMART CLINIC",
          tagline: settings.tagline || "",
          address: settings.address || "",
          phone: settings.phone || "",
          whatsapp: settings.whatsapp || "",
          publicBaseUrl: settings.publicBaseUrl || ""
        });
      }

      // Registration count
      if (url.pathname === "/api/registration-count") {
        const row = await env.DB
          .prepare(
            "SELECT COUNT(*) AS total FROM registrations"
          )
          .first();

        return Response.json({
          ok: true,
          total: Number(row.total || 0)
        });
      }

      return Response.json({
        ok: false,
        error: "Endpoint tidak ditemukan",
        path: url.pathname
      }, { status: 404 });

    } catch (error) {
      return Response.json({
        ok: false,
        build: "77",
        error: String(error)
      }, { status: 500 });
    }
  }
};
