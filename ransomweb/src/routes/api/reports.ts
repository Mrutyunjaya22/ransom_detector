import { createFileRoute } from "@tanstack/react-router";

const BACKEND_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";

export const Route = createFileRoute("/api/reports")({
  server: {
    handlers: {
      GET: async () => {
        const res = await fetch(`${BACKEND_URL}/api/reports`);
        const data = await res.json();
        return Response.json(data, { status: res.status });
      },
    },
  },
});