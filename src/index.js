export default {
  async fetch(request, env) {
    try {
      const result = await env.DB
        .prepare(
          "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        .all();

      return Response.json({
        ok: true,
        build: "75C",
        database: "rsp-smart-clinic-db",
        table_count: result.results.length,
        tables: result.results
      });

    } catch (error) {
      return Response.json({
        ok: false,
        build: "75C",
        error: String(error)
      }, { status: 500 });
    }
  }
};
