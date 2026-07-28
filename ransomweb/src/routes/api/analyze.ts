import { createFileRoute } from "@tanstack/react-router";

export const Route = createFileRoute("/api/analyze")({
  server: {
    handlers: {
      POST: async ({ request }) => {
        const key = process.env.LOVABLE_API_KEY;
        if (!key) {
          return Response.json({ error: "AI model is not configured" }, { status: 503 });
        }

        let payload: unknown;
        try {
          payload = await request.json();
        } catch {
          return Response.json({ error: "Invalid JSON body" }, { status: 400 });
        }

        const { z } = await import("zod");
        const parsed = z
          .object({
            kind: z.enum(["file", "report"]).default("file"),
            subject: z.string().default("unknown"),
            score: z.number(),
            verdict: z.string(),
            reasons: z.array(z.string()).default([]),
            features: z.record(z.number()).default({}),
          })
          .safeParse(payload);
        if (!parsed.success) {
          return Response.json({ error: "Invalid analysis request" }, { status: 400 });
        }
        const data = parsed.data;

        const { generateText, Output, NoObjectGeneratedError } = await import("ai");
        const { createLovableAiGatewayProvider } = await import("@/lib/ai-gateway.server");
        const gateway = createLovableAiGatewayProvider(key, { structuredOutputs: true });

        const schema = z.object({
          summary: z.string(),
          likelyFamily: z.string(),
          confidence: z.number(),
          mitre: z.array(z.string()),
          actions: z.array(z.string()),
          falsePositiveRisk: z.enum(["low", "medium", "high"]),
        });

        const prompt = [
          "You are a malware triage analyst reviewing output from a ransomware detection pipeline.",
          `Artifact type: ${data.kind}`,
          `Subject: ${data.subject}`,
          `Detector score: ${data.score} (verdict: ${data.verdict})`,
          "Heuristic reasons:",
          ...data.reasons.map((r) => `- ${r}`),
          `Features: ${JSON.stringify(data.features)}`,
          "",
          "Give a concise triage. Summary under 60 words, at most 4 MITRE ATT&CK technique ids with names, at most 4 concrete response actions. confidence is between 0 and 1.",
        ].join("\n");

        try {
          const { output } = await generateText({
            model: gateway("google/gemini-3.6-flash"),
            output: Output.object({ schema }),
            prompt,
          });
          return Response.json({ analysis: output });
        } catch (error) {
          if (NoObjectGeneratedError.isInstance(error)) {
            return Response.json({ error: "Model returned an unusable response" }, { status: 502 });
          }
          const message = error instanceof Error ? error.message : "AI analysis failed";
          const status = /429|rate/i.test(message) ? 429 : /402|credit/i.test(message) ? 402 : 502;
          return Response.json({ error: message }, { status });
        }
      },
    },
  },
});
