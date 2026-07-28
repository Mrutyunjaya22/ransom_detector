import { createFileRoute } from "@tanstack/react-router";
import { z } from "zod";

const BACKEND_URL = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";
const bodySchema = z.object({
  mode: z.enum(["benign", "attack"]),
});

export const Route = createFileRoute("/api/run")({
  server: {
    handlers: {
      POST: async ({ request }: { request: Request }) => {
        let raw: unknown;
        try {
          raw = await request.json();
        } catch {
          return Response.json({ error: "Invalid JSON body" }, { status: 400 });
        }
        const parsed = bodySchema.safeParse(raw);
        if (!parsed.success) {
          return Response.json(
            { error: "mode must be 'benign' or 'attack'" },
            { status: 400 },
          );
        }

        const res = await fetch(`${BACKEND_URL}/api/run`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ mode: parsed.data.mode }),
        });
        const data = await res.json();
        return Response.json(data, { status: res.status });
      },
    },
  },
});