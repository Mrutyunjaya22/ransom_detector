import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { StatusPill } from "@/components/StatusPill";
import { FileScanner } from "@/components/FileScanner";
import {
  fetchAlerts,
  fetchReport,
  fetchReports,
  fetchStatus,
  startRun,
  analyzeWithModel,
  type AlertItem,
} from "@/lib/api";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Ransomware Detection Console — Live Pipeline Monitor" },
      {
        name: "description",
        content:
          "Monitor the ransomware detection pipeline: live risk scores, active alerts, model and collector health, plus benign and attack simulation controls.",
      },
      { property: "og:title", content: "Ransomware Detection Console" },
      {
        property: "og:description",
        content:
          "Live risk scoring, alert triage and forensic reports for the ransomware detection prototype.",
      },
      { property: "og:type", content: "website" },
      { name: "twitter:card", content: "summary_large_image" },
    ],
  }),
  component: Dashboard,
});

const STAGES = [
  "collecting",
  "feature-extraction",
  "scoring",
  "correlating",
  "reporting",
];

const STAGE_INFO: Record<string, { label: string; description: string }> = {
  "collecting": {
    label: "Data collection",
    description:
      "The collector captures filesystem changes and process telemetry from the sandboxed workload.",
  },
  "feature-extraction": {
    label: "Feature extraction",
    description:
      "Raw event data is converted into numeric signals such as entropy, file op rate, and extension-change frequency.",
  },
  "scoring": {
    label: "Scoring",
    description:
      "A rules layer and a trained ML model both evaluate behavior, then their outputs are combined into a risk score.",
  },
  "correlating": {
    label: "Correlation",
    description:
      "Suspicious file operations are correlated with process activity to identify malicious campaigns.",
  },
  "reporting": {
    label: "Forensics",
    description:
      "An incident report is assembled with timeline evidence, alerts, and recommended analyst actions.",
  },
};

function severityClass(sev: AlertItem["severity"] | "low" | "medium" | "high" | "critical") {
  return {
    low: "border-border text-muted-foreground",
    medium: "border-warn/50 text-warn",
    high: "border-danger/50 text-danger",
    critical: "border-danger bg-danger/15 text-danger",
  }[sev];
}

function Panel({
  title,
  action,
  children,
  className,
}: {
  title: string;
  action?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <section
      className={cn(
        "rounded-lg border border-border bg-card/70 backdrop-blur-sm",
        className,
      )}
    >
      <header className="flex items-center justify-between border-b border-border px-4 py-3">
        <h2 className="font-mono text-xs uppercase tracking-[0.18em] text-muted-foreground">
          {title}
        </h2>
        {action}
      </header>
      <div className="p-4">{children}</div>
    </section>
  );
}

function Dashboard() {
  const qc = useQueryClient();
  const [openReport, setOpenReport] = useState<string | null>(null);

  const status = useQuery({
    queryKey: ["status"],
    queryFn: fetchStatus,
    refetchInterval: 1500,
  });
  const alerts = useQuery({
    queryKey: ["alerts"],
    queryFn: fetchAlerts,
    refetchInterval: 2000,
  });
  const reports = useQuery({
    queryKey: ["reports"],
    queryFn: fetchReports,
    refetchInterval: 5000,
  });
  const detail = useQuery({
    queryKey: ["report", openReport],
    queryFn: () => fetchReport(openReport!),
    enabled: !!openReport,
  });

  const run = useMutation({
    mutationFn: startRun,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["status"] });
      qc.invalidateQueries({ queryKey: ["alerts"] });
    },
  });

  const reportTriage = useMutation({ mutationFn: analyzeWithModel });

  const s = status.data;
  const analysis = s?.analysis;
  const score = s?.riskScore ?? 0;
  const pct = Math.round(score * 100);
  const over = s ? score >= s.threshold : false;
  const mode = s?.pipeline.mode ?? "idle";
  const running = mode !== "idle";

  return (
    <main className="mx-auto max-w-6xl px-4 py-8 md:px-8">
      <header className="mb-8 flex flex-wrap items-end justify-between gap-4">
        <div>
          <p className="font-mono text-xs uppercase tracking-[0.3em] text-primary">
            prototype console
          </p>
          <h1 className="mt-1 text-3xl font-semibold tracking-tight">
            Ransomware Detection Pipeline
          </h1>
          <p className="mt-1 text-sm text-muted-foreground">
            Live monitoring and demo control for the behavioural detection prototype.
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="secondary"
            disabled={run.isPending || running}
            onClick={() => run.mutate("benign")}
          >
            Run benign workload
          </Button>
          <Button
            variant="destructive"
            disabled={run.isPending || running}
            onClick={() => run.mutate("attack")}
          >
            Run attack simulation
          </Button>
        </div>
      </header>

      <div className="mb-6 grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <StatusPill
          label="Pipeline"
          state={s?.pipeline.healthy ? "ok" : "danger"}
          detail={s?.pipeline.healthy ? "healthy" : "degraded"}
        />
        <StatusPill
          label="ML model"
          state={s?.modelLoaded ? "ok" : "danger"}
          detail={s?.modelLoaded ? "loaded" : "not loaded"}
        />
        <StatusPill
          label="Collector"
          state={s?.collectorActive ? "ok" : "warn"}
          detail={s?.collectorActive ? "running" : "stopped"}
        />
        <StatusPill
          label="Workload mode"
          state={mode === "attack" ? "danger" : mode === "benign" ? "ok" : "idle"}
          detail={mode}
        />
      </div>

      <Panel title="How the pipeline works" className="mb-6">
        <div className="grid gap-4 md:grid-cols-3">
          <div className="rounded-lg border border-border bg-card/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.24em] text-muted-foreground">
              Live analytical flow
            </p>
            <p className="mt-3 text-sm leading-6 text-foreground">
              The system simulates a monitored process, collects file and process telemetry, then detects ransomware-like behavior using both rule-based and ML scoring.
            </p>
          </div>
          <div className="rounded-lg border border-border bg-card/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.24em] text-muted-foreground">
              Why it detects ransomware
            </p>
            <ul className="mt-3 space-y-2 text-sm text-foreground">
              <li>• High entropy on written files suggests encryption.</li>
              <li>• Rapid extension renames indicate ransomware payloads.</li>
              <li>• CPU/IO spikes are correlated with suspicious file activity.</li>
            </ul>
          </div>
          <div className="rounded-lg border border-border bg-card/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.24em] text-muted-foreground">
              What you’re seeing
            </p>
            <p className="mt-3 text-sm leading-6 text-foreground">
              The active stages and evidence feed show how data moves from collection into model scoring and forensic reporting in real time.
            </p>
          </div>
        </div>
      </Panel>

      <Panel title="How it works" className="mb-6">
        <div className="grid gap-4 md:grid-cols-3">
          <div className="rounded-lg border border-border bg-card/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.24em] text-muted-foreground">
              Overview
            </p>
            <p className="mt-3 text-sm leading-6 text-foreground">
              The prototype simulates a monitored process, collects filesystem and process telemetry, extracts ransomware signals, and evaluates behavior with both heuristics and a trained model.
            </p>
          </div>
          <div className="rounded-lg border border-border bg-card/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.24em] text-muted-foreground">
              Why it works
            </p>
            <ul className="mt-3 space-y-2 text-sm text-foreground">
              <li>• High-entropy writes often indicate encryption activity.</li>
              <li>• Rapid extension changes signal mass file tampering.</li>
              <li>• Process CPU/IO spikes are correlated with suspicious file operations.</li>
            </ul>
          </div>
          <div className="rounded-lg border border-border bg-card/70 p-4">
            <p className="font-mono text-[11px] uppercase tracking-[0.24em] text-muted-foreground">
              What you’re seeing
            </p>
            <p className="mt-3 text-sm leading-6 text-foreground">
              The live evidence feed tracks model score updates and rule-based signals as they appear, so you can follow the detection flow in real time.
            </p>
          </div>
        </div>
      </Panel>

      <div className="grid gap-6 lg:grid-cols-3">
        <Panel title="Risk score" className="lg:col-span-2">
          <div className="flex items-baseline justify-between">
            <div>
              <p className="font-mono text-5xl font-semibold tabular-nums">
                {score.toFixed(3)}
              </p>
              <p className="mt-1 text-sm text-muted-foreground">
                {s?.monitoredProcess.name ?? "—"}{" "}
                <span className="font-mono">pid {s?.monitoredProcess.pid ?? "—"}</span>
              </p>
            </div>
            <Badge
              variant="outline"
              className={cn(
                "font-mono",
                over ? "border-danger text-danger" : "border-ok text-ok",
              )}
            >
              {over ? "ABOVE THRESHOLD" : "NOMINAL"}
            </Badge>
          </div>

          <Progress
            value={pct}
            className={cn("mt-4 h-3", over && "[&>div]:bg-danger")}
          />
          <div className="mt-2 flex justify-between font-mono text-xs text-muted-foreground">
            <span>0.000</span>
            <span>threshold {s?.threshold.toFixed(2) ?? "0.60"}</span>
            <span>1.000</span>
          </div>

          <div className="mt-6 flex flex-wrap gap-2">
            {STAGES.map((stage) => {
              const active = s?.pipeline.stage === stage;
              const idx = STAGES.indexOf(s?.pipeline.stage ?? "");
              const done = idx > STAGES.indexOf(stage);
              return (
                <span
                  key={stage}
                  className={cn(
                    "rounded border px-2.5 py-1 font-mono text-xs",
                    active
                      ? "border-primary bg-primary/15 text-primary"
                      : done
                        ? "border-ok/40 text-ok"
                        : "border-border text-muted-foreground",
                  )}
                >
                  {stage}
                </span>
              );
            })}
          </div>

          <dl className="mt-6 grid grid-cols-3 gap-4 border-t border-border pt-4 font-mono text-sm">
            <div>
              <dt className="text-xs uppercase text-muted-foreground">Stage</dt>
              <dd>{s?.pipeline.stage ?? "—"}</dd>
            </div>
            <div>
              <dt className="text-xs uppercase text-muted-foreground">Events</dt>
              <dd className="tabular-nums">
                {s?.pipeline.eventsProcessed.toLocaleString() ?? "—"}
              </dd>
            </div>
            <div>
              <dt className="text-xs uppercase text-muted-foreground">Uptime</dt>
              <dd className="tabular-nums">{s?.pipeline.uptimeSec ?? 0}s</dd>
            </div>
          </dl>
        </Panel>

        <Panel
          title="Active alerts"
          action={
            <Badge variant="outline" className="font-mono">
              {alerts.data?.count ?? 0}
            </Badge>
          }
        >
          {!alerts.data?.alerts.length ? (
            <p className="py-8 text-center text-sm text-muted-foreground">
              No active alerts.
            </p>
          ) : (
            <ul className="space-y-3">
              {alerts.data.alerts.map((a) => (
                <li
                  key={a.id}
                  className={cn("rounded-md border p-3", severityClass(a.severity))}
                >
                  <div className="flex items-center justify-between font-mono text-xs">
                    <span className="uppercase tracking-wider">{a.severity}</span>
                    <span className="tabular-nums">{a.score.toFixed(3)}</span>
                  </div>
                  <p className="mt-1 font-mono text-sm text-foreground">
                    {a.process} · {a.pid}
                  </p>
                  <ul className="mt-2 space-y-1 text-xs text-muted-foreground">
                    {a.reasons.map((r) => (
                      <li key={r}>— {r}</li>
                    ))}
                  </ul>
                </li>
              ))}
            </ul>
          )}
        </Panel>

        <Panel title="Multi-stage behavioral analysis" className="lg:col-span-3">
          <div className="grid gap-4 xl:grid-cols-[1.2fr_0.8fr]">
            <div className="space-y-3">
              {analysis?.activeStages.map((stage) => (
                <div
                  key={stage.name}
                  className={cn(
                    "rounded-lg border p-3",
                    stage.status === "active"
                      ? "border-primary/50 bg-primary/10"
                      : stage.status === "complete"
                        ? "border-ok/40 bg-ok/10"
                        : "border-border bg-card/50",
                  )}
                >
                  <div className="flex items-center justify-between gap-3">
                    <div>
                      <p className="font-mono text-[11px] uppercase tracking-[0.2em] text-muted-foreground">
                        {stage.name}
                      </p>
                      <p className="mt-1 text-sm text-foreground">{stage.detail}</p>
                    </div>
                    <Badge
                      variant="outline"
                      className={cn(
                        "font-mono text-[10px] uppercase",
                        stage.status === "active"
                          ? "border-primary text-primary"
                          : stage.status === "complete"
                            ? "border-ok text-ok"
                            : "border-border text-muted-foreground",
                      )}
                    >
                      {stage.status}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>

            <div className="rounded-lg border border-border bg-surface/70 p-4">
              <p className="font-mono text-[11px] uppercase tracking-[0.24em] text-muted-foreground">
                Live summary
              </p>
              <div className="mt-3 space-y-3 text-sm">
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Risk</span>
                  <span className="font-mono tabular-nums">{analysis?.summary.riskScore.toFixed(3) ?? "0.000"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Rule</span>
                  <span className="font-mono tabular-nums">{analysis?.summary.ruleScore.toFixed(3) ?? "0.000"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">ML</span>
                  <span className="font-mono tabular-nums">{analysis?.summary.mlScore.toFixed(3) ?? "0.000"}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Signals</span>
                  <span className="font-mono tabular-nums">{analysis?.summary.suspiciousSignals ?? 0}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-muted-foreground">Forensic ready</span>
                  <span className={cn("font-mono", analysis?.summary.forensicReady ? "text-ok" : "text-muted-foreground") }>
                    {analysis?.summary.forensicReady ? "yes" : "no"}
                  </span>
                </div>
              </div>
            </div>
          </div>

          <div className="mt-4 space-y-2">
            <p className="font-mono text-[11px] uppercase tracking-[0.24em] text-muted-foreground">
              evidence feed
            </p>
            {!analysis?.evidence.length ? (
              <p className="rounded border border-border bg-card/40 p-3 text-sm text-muted-foreground">
                Waiting for behavioral evidence to appear.
              </p>
            ) : (
              <ul className="space-y-2">
                {analysis.evidence.map((item) => (
                  <li key={`${item.timestamp}-${item.stage}`} className={cn("rounded border p-3", severityClass(item.severity))}>
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="font-mono text-[11px] uppercase tracking-[0.2em]">
                        {item.stage}
                      </p>
                      <span className="font-mono text-[11px] text-muted-foreground">
                        {new Date(item.timestamp * 1000).toLocaleTimeString()}
                      </span>
                    </div>
                    <p className="mt-1 text-sm">{item.detail}</p>
                    {item.signals.length > 0 && (
                      <ul className="mt-2 space-y-1 text-xs text-muted-foreground">
                        {item.signals.map((signal) => (
                          <li key={signal}>• {signal}</li>
                        ))}
                      </ul>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </div>
        </Panel>

        <Panel title="Scan a file with the model" className="lg:col-span-3">
          <FileScanner />
        </Panel>

        <Panel title="Recent forensic reports" className="lg:col-span-3">
          {!reports.data?.reports.length ? (
            <p className="py-6 text-center text-sm text-muted-foreground">
              No reports yet — run a workload to generate one.
            </p>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-left text-sm">
                <thead className="font-mono text-xs uppercase tracking-wider text-muted-foreground">
                  <tr className="border-b border-border">
                    <th className="pb-2">Report</th>
                    <th className="pb-2">Mode</th>
                    <th className="pb-2">Process</th>
                    <th className="pb-2">Verdict</th>
                    <th className="pb-2">Peak</th>
                    <th className="pb-2">Alerts</th>
                    <th className="pb-2">Created</th>
                    <th />
                  </tr>
                </thead>
                <tbody className="font-mono">
                  {reports.data.reports.map((r) => (
                    <tr key={r.id} className="border-b border-border/60 last:border-0">
                      <td className="py-2.5">{r.id}</td>
                      <td>{r.mode}</td>
                      <td>{r.process}</td>
                      <td
                        className={cn(
                          r.verdict === "malicious"
                            ? "text-danger"
                            : r.verdict === "suspicious"
                              ? "text-warn"
                              : "text-ok",
                        )}
                      >
                        {r.verdict}
                      </td>
                      <td className="tabular-nums">{r.peakScore.toFixed(3)}</td>
                      <td className="tabular-nums">{r.alertCount}</td>
                      <td className="text-muted-foreground">
                        {new Date(r.createdAt).toLocaleTimeString()}
                      </td>
                      <td className="text-right">
                        <Button
                          size="sm"
                          variant="ghost"
                          onClick={() => setOpenReport(r.id)}
                        >
                          View
                        </Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </div>

      <Dialog open={!!openReport} onOpenChange={(o) => !o && setOpenReport(null)}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl">
          <DialogHeader>
            <DialogTitle className="font-mono">
              Report {detail.data?.report.id ?? openReport}
            </DialogTitle>
            <DialogDescription>
              {detail.data
                ? `${detail.data.report.mode} workload · ${detail.data.report.process} (pid ${detail.data.report.pid})`
                : "Loading report details…"}
            </DialogDescription>
          </DialogHeader>

          {detail.data && (
            <div className="space-y-5 text-sm">
              <div className="grid grid-cols-3 gap-3 font-mono">
                <div>
                  <p className="text-xs uppercase text-muted-foreground">Verdict</p>
                  <p>{detail.data.report.verdict}</p>
                </div>
                <div>
                  <p className="text-xs uppercase text-muted-foreground">Peak score</p>
                  <p className="tabular-nums">{detail.data.report.peakScore.toFixed(3)}</p>
                </div>
                <div>
                  <p className="text-xs uppercase text-muted-foreground">Duration</p>
                  <p className="tabular-nums">{detail.data.report.durationSec}s</p>
                </div>
              </div>

              <div>
                <p className="mb-2 font-mono text-xs uppercase tracking-wider text-muted-foreground">
                  Features
                </p>
                <ul className="grid grid-cols-2 gap-2 font-mono text-xs">
                  {Object.entries(detail.data.report.features).map(([k, v]) => (
                    <li
                      key={k}
                      className="flex justify-between rounded border border-border px-2 py-1"
                    >
                      <span className="text-muted-foreground">{k}</span>
                      <span className="tabular-nums">{v}</span>
                    </li>
                  ))}
                </ul>
              </div>

              <div>
                <p className="mb-2 font-mono text-xs uppercase tracking-wider text-muted-foreground">
                  Timeline
                </p>
                <ul className="space-y-1 font-mono text-xs">
                  {detail.data.report.timeline.map((e) => (
                    <li key={e.t} className="flex items-center gap-3">
                      <span className="w-10 tabular-nums text-muted-foreground">
                        +{e.t}s
                      </span>
                      <span className="w-14 tabular-nums">{e.score.toFixed(2)}</span>
                      <span>{e.event}</span>
                    </li>
                  ))}
                </ul>
              </div>

              {detail.data.report.alerts.length > 0 && (
                <div>
                  <p className="mb-2 font-mono text-xs uppercase tracking-wider text-muted-foreground">
                    Alerts
                  </p>
                  <ul className="space-y-2">
                    {detail.data.report.alerts.map((a) => (
                      <li
                        key={a.id}
                        className={cn("rounded border p-2 text-xs", severityClass(a.severity))}
                      >
                        <span className="font-mono uppercase">{a.severity}</span> —{" "}
                        {a.reasons.join("; ")}
                      </li>
                    ))}
                  </ul>
                </div>
              )}

              <p className="rounded border border-border bg-surface p-3 text-sm">
                <span className="font-mono text-xs uppercase text-muted-foreground">
                  Recommendation
                </span>
                <br />
                {detail.data.report.recommendation}
              </p>

              <div>
                <Button
                  size="sm"
                  variant="secondary"
                  disabled={reportTriage.isPending}
                  onClick={() =>
                    reportTriage.mutate({
                      kind: "report",
                      subject: `${detail.data!.report.process} (${detail.data!.report.mode} workload)`,
                      score: detail.data!.report.peakScore,
                      verdict: detail.data!.report.verdict,
                      reasons: detail.data!.report.alerts.flatMap((a) => a.reasons),
                      features: detail.data!.report.features,
                    })
                  }
                >
                  {reportTriage.isPending ? "Model reasoning…" : "Run AI triage on report"}
                </Button>

                {reportTriage.isError && (
                  <p className="mt-2 rounded border border-danger/50 bg-danger/10 p-2 text-xs text-danger">
                    {(reportTriage.error as Error).message}
                  </p>
                )}

                {reportTriage.data && (
                  <div className="mt-3 rounded-md border border-primary/40 bg-primary/5 p-3">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <p className="font-mono text-xs uppercase tracking-wider text-primary">
                        AI triage · {reportTriage.data.likelyFamily}
                      </p>
                      <span className="font-mono text-xs text-muted-foreground">
                        confidence {(reportTriage.data.confidence * 100).toFixed(0)}% · FP risk{" "}
                        {reportTriage.data.falsePositiveRisk}
                      </span>
                    </div>
                    <p className="mt-2 text-sm">{reportTriage.data.summary}</p>
                    <div className="mt-3 flex flex-wrap gap-1">
                      {reportTriage.data.mitre.map((m) => (
                        <Badge key={m} variant="outline" className="font-mono text-[10px]">
                          {m}
                        </Badge>
                      ))}
                    </div>
                    <ul className="mt-3 space-y-1 text-xs text-muted-foreground">
                      {reportTriage.data.actions.map((a) => (
                        <li key={a}>→ {a}</li>
                      ))}
                    </ul>
                  </div>
                )}
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </main>
  );
}
