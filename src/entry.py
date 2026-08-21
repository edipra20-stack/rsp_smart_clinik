from workers import Response, WorkerEntrypoint


class Default(WorkerEntrypoint):
    async def fetch(self, request):
        try:
            results = await self.env.DB.prepare(
                "PRAGMA table_list"
            ).run()

            return Response.json({
                "ok": True,
                "build": "75B",
                "database": "rsp-smart-clinic-db",
                "tables": results
            })

        except Exception as e:
            return Response.json({
                "ok": False,
                "build": "75B",
                "error": str(e)
            }, status=500)
