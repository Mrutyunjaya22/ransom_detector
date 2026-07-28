import { createFileRoute } from "@tanstack/react-router";

const BACKEND_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";
const MAX_BYTES = 8 * 1024 * 1024;

export const Route = createFileRoute("/api/scan")({
  server: {
    handlers: {
      GET: async () => {
        const res = await fetch(`${BACKEND_URL}/api/scan`);
        const data = await res.json();
        return Response.json(data, { status: res.status });
      },
      POST: async ({ request }: { request: Request }) => {
        let form: FormData;
        try {
          form = await request.formData();
        } catch {
          return Response.json({ error: "Expected multipart/form-data" }, { status: 400 });
        }
        const file = form.get("file");
        if (!(file instanceof File)) {
          return Response.json({ error: "Missing 'file' field" }, { status: 400 });
        }
        if (file.size > MAX_BYTES) {
          return Response.json({ error: "File exceeds 8 MB scan limit" }, { status: 413 });
        }
        const body = new FormData();
        body.append("file", file);
        const res = await fetch(`${BACKEND_URL}/api/scan`, {
          method: "POST",
          body,
        });
        const data = await res.json();
        return Response.json(data, { status: res.status });
      },
    },
  },
});