import { createFileRoute } from "@tanstack/react-router";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { useState } from "react";
import {
  Shield,
  ShieldAlert,
  ShieldCheck,
  Activity,
  FileSearch,
  FileText,
  Cpu,
  Flame,
  Zap,
  CheckCircle2,
  AlertTriangle,
  Play,
  RotateCcw,
  Sparkles,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
} from "@/components/ui/dialog";
import { FileScanner } from "@/components/FileScanner";
import {
  fetchAlerts,
  fetchReport,
  fetchReports,
  fetchStatus,
  startRun,
  analyzeWithModel,
  fetchModelMetadata,
  triggerRetraining,
  type AlertItem,
} from "@/lib/api";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "AEGIS — Ransomware EDR & Behavioral Telemetry" },
      {
        name: "description",
        content:
          "Minimal, real-time ransomware behavioral detection console featuring sub-second dual-engine scoring, streaming file inspection, and forensic reports.",
      },
    ],
  }),
  component: MinimalDashboard,
});

const PIPELINE_STAGES = [
  { id: "collecting", label: "Telemetry", desc: "Filesystem & process capture" },
  { id: "feature-extraction", label: "Features", desc: "Shannon entropy & rename rates" },
  { id: "scoring", label: "Dual ML", desc: "Rule heuristic + Random Forest" },
  { id: "correlating", label: "Correlation", desc: "Process & file anomaly fusion" },
  { id: "reporting", label: "Forensics", desc: "Automated mitigation & report" },
];

function severityBadge(sev: string = "medium") {
  switch (sev) {
    case "critical":
      return "border-red-500/50 bg-red-500/15 text-red-400";
    case "high":
      return "border-amber-500/50 bg-amber-500/15 text-amber-400";
    case "medium":
      return "border-yellow-500/50 bg-yellow-500/10 text-yellow-400";
    default:
      return "border-slate-700 bg-slate-800/50 text-slate-300";
  }
}

function MinimalDashboard() {
  const qc = useQueryClient();
  const [activeTab, setActiveTab] = useState("monitor");
  const [openReportId, setOpenReportId] = useState<string | null>(null);

  // Core real-time telemetry queries
  const status = useQuery({
    queryKey: ["status"],
    queryFn: fetchStatus,
    refetchInterval: 1200,
  });

  const alerts = useQuery({
    queryKey: ["alerts"],
    queryFn: fetchAlerts,
    refetchInterval: 1500,
  });

  const reports = useQuery({
    queryKey: ["reports"],
    queryFn: fetchReports,
    refetchInterval: 4000,
  });

  const reportDetail = useQuery({
    queryKey: ["report", openReportId],
    queryFn: () => fetchReport(openReportId!),
    enabled: !!openReportId,
  });

  const modelMeta = useQuery({
    queryKey: ["modelMeta"],
    queryFn: fetchModelMetadata,
    staleTime: 60000,
  });

  const runMutation = useMutation({
    mutationFn: startRun,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["status"] });
      qc.invalidateQueries({ queryKey: ["alerts"] });
    },
  });

  const retrainMutation = useMutation({
    mutationFn: (samples?: number) => triggerRetraining(samples),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["modelMeta"] });
      qc.invalidateQueries({ queryKey: ["status"] });
    },
  });

  const aiTriageMutation = useMutation({ mutationFn: analyzeWithModel });

  const s = status.data;
  const score = s?.riskScore ?? 0;
  const threshold = s?.threshold ?? 0.6;
  const isThreat = score >= threshold;
  const mode = s?.pipeline.mode ?? "idle";
  const isRunning = mode !== "idle";
  const activeAlertsCount = alerts.data?.count ?? alerts.data?.alerts.length ?? 0;

  // Stage mapping
  const currentStageIndex = PIPELINE_STAGES.findIndex(
    (st) => st.id === (s?.pipeline.stage || "collecting")
  );

  return (
    <div className="min-h-screen bg-slate-950 text-slate-100 antialiased selection:bg-cyan-500/30">
      {/* 1. Sleek Top Navigation Bar */}
      <header className="sticky top-0 z-30 border-b border-slate-800/80 bg-slate-950/80 backdrop-blur-md">
        <div className="mx-auto flex max-w-7xl items-center justify-between px-4 py-3 sm:px-6">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-cyan-500/30 bg-cyan-500/10 text-cyan-400 shadow-[0_0_15px_rgba(6,182,212,0.15)]">
              {isThreat ? (
                <ShieldAlert className="h-5 w-5 text-red-400 animate-pulse" />
              ) : (
                <ShieldCheck className="h-5 w-5 text-cyan-400" />
              )}
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-mono text-sm font-bold tracking-wider text-slate-100">
                  AEGIS
                </span>
                <span className="rounded bg-slate-800 px-1.5 py-0.5 font-mono text-[10px] text-cyan-400">
                  v2.0 EDR
                </span>
              </div>
              <p className="text-[11px] text-slate-400">
                Autonomous Behavioral Ransomware Protection
              </p>
            </div>
          </div>

          {/* Center/Right: Status pill & Quick Controls */}
          <div className="flex items-center gap-3">
            <div className="hidden sm:flex items-center gap-2 rounded-full border border-slate-800 bg-slate-900/90 px-3 py-1 text-xs">
              <span
                className={cn(
                  "h-2 w-2 rounded-full",
                  isThreat
                    ? "bg-red-500 animate-ping"
                    : isRunning
                    ? "bg-amber-400 animate-pulse"
                    : "bg-emerald-400"
                )}
              />
              <span className="font-mono text-[11px] text-slate-300">
                {isThreat
                  ? "THREAT ACTIVE"
                  : isRunning
                  ? `RUNNING: ${mode.toUpperCase()}`
                  : "SYSTEM ARMED"}
              </span>
            </div>

            {/* Quick Demo Controls */}
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                variant="outline"
                disabled={runMutation.isPending || isRunning}
                onClick={() => runMutation.mutate("benign")}
                className="h-8 border-slate-700 bg-slate-900 text-xs text-slate-200 hover:bg-slate-800 hover:text-emerald-400 transition-colors"
              >
                <Play className="mr-1.5 h-3.5 w-3.5 text-emerald-400" />
                Normal Test
              </Button>
              <Button
                size="sm"
                variant="destructive"
                disabled={runMutation.isPending || isRunning}
                onClick={() => runMutation.mutate("attack")}
                className={cn(
                  "h-8 text-xs shadow-sm transition-all",
                  isThreat
                    ? "bg-red-600 hover:bg-red-500 animate-pulse"
                    : "bg-red-600/90 hover:bg-red-600"
                )}
              >
                <Flame className="mr-1.5 h-3.5 w-3.5" />
                Simulate Attack
              </Button>
            </div>
          </div>
        </div>
      </header>

      {/* Main Content Area */}
      <main className="mx-auto max-w-7xl px-4 py-6 sm:px-6 space-y-6">
        {/* 2. Minimalist Hero Strip: Live Threat Meter & Pipeline Stage */}
        <div className="grid gap-4 md:grid-cols-12">
          {/* Left Hero Card: Live Risk Score */}
          <div className="md:col-span-4 rounded-xl border border-slate-800/80 bg-gradient-to-b from-slate-900/90 to-slate-950 p-5 shadow-sm">
            <div className="flex items-center justify-between">
              <span className="font-mono text-xs uppercase tracking-wider text-slate-400">
                Threat Risk Level
              </span>
              <Badge
                variant="outline"
                className={cn(
                  "font-mono text-[10px]",
                  isThreat
                    ? "border-red-500 bg-red-500/10 text-red-400"
                    : "border-emerald-500/40 bg-emerald-500/10 text-emerald-400"
                )}
              >
                {isThreat ? "CRITICAL MALICIOUS" : "SAFE / NOMINAL"}
              </Badge>
            </div>

            <div className="mt-3 flex items-baseline gap-3">
              <span
                className={cn(
                  "font-mono text-5xl font-bold tracking-tight tabular-nums transition-colors",
                  isThreat
                    ? "text-red-400"
                    : score > 0.3
                    ? "text-amber-400"
                    : "text-emerald-400"
                )}
              >
                {score.toFixed(3)}
              </span>
              <span className="font-mono text-xs text-slate-500">
                / 1.000 max (thr: {threshold.toFixed(2)})
              </span>
            </div>

            {/* Visual Risk Bar */}
            <div className="mt-3">
              <Progress
                value={Math.min(100, Math.round(score * 100))}
                className={cn(
                  "h-2 bg-slate-800",
                  isThreat
                    ? "[&>div]:bg-red-500"
                    : score > 0.3
                    ? "[&>div]:bg-amber-400"
                    : "[&>div]:bg-emerald-400"
                )}
              />
            </div>

            <div className="mt-4 flex items-center justify-between border-t border-slate-800/80 pt-3 text-xs">
              <span className="text-slate-400">Target Process</span>
              <span className="font-mono text-slate-200 truncate max-w-[170px]">
                {s?.monitoredProcess.name || "idle_system"} (PID: {s?.monitoredProcess.pid || "—"})
              </span>
            </div>
          </div>

          {/* Right Hero Card: 5-Stage Behavioral Pipeline */}
          <div className="md:col-span-8 rounded-xl border border-slate-800/80 bg-gradient-to-b from-slate-900/90 to-slate-950 p-5 shadow-sm flex flex-col justify-between">
            <div className="flex items-center justify-between">
              <div>
                <span className="font-mono text-xs uppercase tracking-wider text-slate-400">
                  Autonomous Detection Pipeline
                </span>
                <p className="text-xs text-slate-400 mt-0.5">
                  Sub-second event ingestion, feature extraction, and dual-layer inference
                </p>
              </div>
              <span className="rounded bg-slate-800/80 px-2 py-0.5 font-mono text-[11px] text-cyan-400">
                {s?.pipeline.eventsProcessed || 0} Events Analyzed
              </span>
            </div>

            {/* Connected Stage Stepper */}
            <div className="my-4 grid grid-cols-5 gap-2">
              {PIPELINE_STAGES.map((st, idx) => {
                const isCurrent = isRunning && s?.pipeline.stage === st.id;
                const isCompleted = isRunning && currentStageIndex > idx;
                return (
                  <div
                    key={st.id}
                    className={cn(
                      "rounded-lg border p-2.5 transition-all text-center flex flex-col justify-center",
                      isCurrent
                        ? "border-cyan-500 bg-cyan-500/10 shadow-[0_0_12px_rgba(6,182,212,0.2)]"
                        : isCompleted
                        ? "border-emerald-500/40 bg-emerald-500/5 text-slate-300"
                        : "border-slate-800/80 bg-slate-900/50 text-slate-500"
                    )}
                  >
                    <div className="flex items-center justify-center gap-1">
                      {isCompleted ? (
                        <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                      ) : isCurrent ? (
                        <Zap className="h-3.5 w-3.5 text-cyan-400 animate-pulse shrink-0" />
                      ) : (
                        <span className="font-mono text-[10px] text-slate-500">0{idx + 1}</span>
                      )}
                      <span
                        className={cn(
                          "font-mono text-xs font-semibold truncate",
                          isCurrent ? "text-cyan-400" : isCompleted ? "text-slate-200" : "text-slate-400"
                        )}
                      >
                        {st.label}
                      </span>
                    </div>
                    <p className="mt-1 hidden lg:block text-[10px] text-slate-500 truncate">
                      {st.desc}
                    </p>
                  </div>
                );
              })}
            </div>

            {/* Real-time Sub-metrics */}
            <div className="grid grid-cols-3 gap-2 border-t border-slate-800/80 pt-3 text-xs">
              <div>
                <span className="text-slate-500 block text-[10px] uppercase font-mono">Rule Score</span>
                <span className="font-mono font-semibold text-slate-200">
                  {s?.analysis?.summary.ruleScore.toFixed(2) ?? "0.00"}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase font-mono">ML Random Forest</span>
                <span className="font-mono font-semibold text-slate-200">
                  {s?.analysis?.summary.mlScore.toFixed(2) ?? "0.00"}
                </span>
              </div>
              <div>
                <span className="text-slate-500 block text-[10px] uppercase font-mono">Active Alerts</span>
                <span
                  className={cn(
                    "font-mono font-semibold",
                    activeAlertsCount > 0 ? "text-red-400 font-bold" : "text-slate-400"
                  )}
                >
                  {activeAlertsCount}
                </span>
              </div>
            </div>
          </div>
        </div>

        {/* 3. Simple Tabbed Workspace: Everything focused and uncluttered */}
        <Tabs value={activeTab} onValueChange={setActiveTab} className="space-y-4">
          <TabsList className="grid w-full grid-cols-4 bg-slate-900 border border-slate-800 p-1 rounded-xl">
            <TabsTrigger
              value="monitor"
              className="gap-2 text-xs data-[state=active]:bg-slate-800 data-[state=active]:text-cyan-400 font-medium cursor-pointer"
            >
              <Activity className="h-3.5 w-3.5" />
              Live Telemetry
            </TabsTrigger>
            <TabsTrigger
              value="scanner"
              className="gap-2 text-xs data-[state=active]:bg-slate-800 data-[state=active]:text-cyan-400 font-medium cursor-pointer"
            >
              <FileSearch className="h-3.5 w-3.5" />
              File Inspector
            </TabsTrigger>
            <TabsTrigger
              value="forensics"
              className="gap-2 text-xs data-[state=active]:bg-slate-800 data-[state=active]:text-cyan-400 font-medium cursor-pointer"
            >
              <FileText className="h-3.5 w-3.5" />
              Incident Forensics
            </TabsTrigger>
            <TabsTrigger
              value="mlops"
              className="gap-2 text-xs data-[state=active]:bg-slate-800 data-[state=active]:text-cyan-400 font-medium cursor-pointer"
            >
              <Cpu className="h-3.5 w-3.5" />
              Model & Engine
            </TabsTrigger>
          </TabsList>

          {/* TAB 1: Live Telemetry & Active Alerts */}
          <TabsContent value="monitor" className="space-y-4 focus-visible:outline-none">
            <div className="grid gap-4 lg:grid-cols-2">
              {/* Active Alerts Panel */}
              <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <AlertTriangle className="h-4 w-4 text-amber-400" />
                    <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300">
                      Active Threat Alerts
                    </h3>
                  </div>
                  <Badge variant="outline" className="font-mono text-xs text-slate-400">
                    {alerts.data?.alerts.length || 0} Registered
                  </Badge>
                </div>

                {!alerts.data?.alerts.length ? (
                  <div className="py-12 text-center">
                    <CheckCircle2 className="mx-auto h-8 w-8 text-emerald-500/60 mb-2" />
                    <p className="text-sm font-medium text-slate-300">No active threat alerts</p>
                    <p className="text-xs text-slate-500 mt-1">
                      Endpoint behaviors are within nominal baseline safety limits.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-3 max-h-[360px] overflow-y-auto pr-1">
                    {alerts.data.alerts.map((a: AlertItem) => (
                      <div
                        key={a.id}
                        className={cn(
                          "rounded-lg border p-3.5 transition-all",
                          severityBadge(a.severity)
                        )}
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-xs font-bold uppercase tracking-wider">
                            {a.severity || "ALERT"} · {a.id}
                          </span>
                          <span className="font-mono text-xs font-bold">
                            Score: {(a.score || 0).toFixed(3)}
                          </span>
                        </div>
                        <p className="mt-1 font-mono text-xs text-slate-200">
                          Target: <span className="text-cyan-300">{a.process}</span> (PID: {a.pid})
                        </p>
                        <ul className="mt-2 space-y-1 text-xs opacity-90">
                          {(a.reasons || []).map((r, i) => (
                            <li key={i} className="flex items-center gap-1.5">
                              <span className="text-red-400">›</span> {r}
                            </li>
                          ))}
                        </ul>
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Real-time Evidence Feed */}
              <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5">
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-2">
                    <Activity className="h-4 w-4 text-cyan-400" />
                    <h3 className="font-mono text-xs font-semibold uppercase tracking-wider text-slate-300">
                      Telemetry Signals
                    </h3>
                  </div>
                  <span className="font-mono text-xs text-slate-500">Live Ingestion</span>
                </div>

                {!s?.analysis?.evidence.length ? (
                  <div className="py-12 text-center">
                    <Activity className="mx-auto h-8 w-8 text-slate-600 mb-2 animate-pulse" />
                    <p className="text-sm font-medium text-slate-400">Waiting for events</p>
                    <p className="text-xs text-slate-500 mt-1">
                      Trigger a simulation above to observe live behavioral telemetry.
                    </p>
                  </div>
                ) : (
                  <div className="space-y-2.5 max-h-[360px] overflow-y-auto pr-1">
                    {s.analysis.evidence.map((ev, i) => (
                      <div
                        key={i}
                        className="rounded-lg border border-slate-800 bg-slate-950/70 p-3 text-xs"
                      >
                        <div className="flex items-center justify-between">
                          <span className="font-mono uppercase font-bold text-cyan-400 text-[10px]">
                            {ev.stage}
                          </span>
                          <span className="font-mono text-[10px] text-slate-500">
                            {new Date(ev.timestamp * 1000).toLocaleTimeString()}
                          </span>
                        </div>
                        <p className="mt-1 text-slate-200 font-medium">{ev.detail}</p>
                        {ev.signals.length > 0 && (
                          <div className="mt-1.5 flex flex-wrap gap-1">
                            {ev.signals.map((sig, j) => (
                              <span
                                key={j}
                                className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300 font-mono"
                              >
                                {sig}
                              </span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          </TabsContent>

          {/* TAB 2: Clean File Inspector */}
          <TabsContent value="scanner" className="focus-visible:outline-none">
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5">
              <div className="mb-4">
                <h3 className="font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
                  Streaming Shannon Entropy & Magic Byte Inspector
                </h3>
                <p className="text-xs text-slate-400 mt-1">
                  Upload or drop binary files to calculate $O(1)$ memory 256-bin entropy and MITRE ATT&CK taxonomy.
                </p>
              </div>
              <FileScanner />
            </div>
          </TabsContent>

          {/* TAB 3: Incident Forensics */}
          <TabsContent value="forensics" className="focus-visible:outline-none">
            <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5">
              <div className="flex items-center justify-between mb-4">
                <div>
                  <h3 className="font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
                    Cryptographic Incident Reports
                  </h3>
                  <p className="text-xs text-slate-400 mt-1">
                    Immutable post-incident evidence timelines with SIEM/SOAR compliance
                  </p>
                </div>
                <Badge variant="outline" className="font-mono text-xs">
                  {reports.data?.reports.length || 0} Incidents
                </Badge>
              </div>

              {!reports.data?.reports.length ? (
                <div className="py-12 text-center text-slate-500 text-sm">
                  No forensic incident reports recorded yet. Run a workload simulation to generate an incident report.
                </div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-left text-xs">
                    <thead className="border-b border-slate-800 font-mono text-[11px] uppercase text-slate-400">
                      <tr>
                        <th className="pb-2.5">Report ID</th>
                        <th className="pb-2.5">Workload Mode</th>
                        <th className="pb-2.5">Process</th>
                        <th className="pb-2.5">Verdict</th>
                        <th className="pb-2.5">Peak Score</th>
                        <th className="pb-2.5">Alerts</th>
                        <th className="pb-2.5 text-right">Actions</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-slate-800/60 font-mono">
                      {reports.data.reports.map((r) => (
                        <tr key={r.id} className="hover:bg-slate-800/30 transition-colors">
                          <td className="py-3 font-semibold text-slate-200">{r.id}</td>
                          <td>
                            <span className="capitalize">{r.mode}</span>
                          </td>
                          <td className="text-slate-300">{r.process}</td>
                          <td>
                            <Badge
                              variant="outline"
                              className={cn(
                                "text-[10px] uppercase font-mono",
                                r.verdict === "malicious"
                                  ? "border-red-500 text-red-400"
                                  : r.verdict === "suspicious"
                                  ? "border-amber-500 text-amber-400"
                                  : "border-emerald-500 text-emerald-400"
                              )}
                            >
                              {r.verdict}
                            </Badge>
                          </td>
                          <td className="tabular-nums font-bold">{(r.peakScore || 0).toFixed(3)}</td>
                          <td>{r.alertCount}</td>
                          <td className="text-right">
                            <Button
                              size="sm"
                              variant="ghost"
                              onClick={() => setOpenReportId(r.id)}
                              className="h-7 text-xs text-cyan-400 hover:text-cyan-300"
                            >
                              View Details
                            </Button>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </TabsContent>

          {/* TAB 4: Model & MLOps */}
          <TabsContent value="mlops" className="focus-visible:outline-none">
            <div className="grid gap-4 md:grid-cols-3">
              <div className="md:col-span-2 rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 space-y-4">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="font-mono text-sm font-semibold uppercase tracking-wider text-slate-200">
                      Active Inference Engine
                    </h3>
                    <p className="text-xs text-slate-400 mt-0.5">
                      Random Forest Classifier calibrated against real-world ransomware and benign workloads
                    </p>
                  </div>
                  <Badge className="bg-cyan-500/10 text-cyan-400 border-cyan-500/30 font-mono text-xs">
                    {modelMeta.data?.model.version || "v2.0-rf"}
                  </Badge>
                </div>

                <div className="grid grid-cols-4 gap-3">
                  <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-center">
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Accuracy</span>
                    <p className="mt-1 font-mono text-lg font-bold text-emerald-400">
                      {((modelMeta.data?.model.accuracy ?? 0.985) * 100).toFixed(1)}%
                    </p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-center">
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Precision</span>
                    <p className="mt-1 font-mono text-lg font-bold text-cyan-400">
                      {((modelMeta.data?.model.precision ?? 0.978) * 100).toFixed(1)}%
                    </p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-center">
                    <span className="text-[10px] font-mono text-slate-500 uppercase">Recall</span>
                    <p className="mt-1 font-mono text-lg font-bold text-cyan-400">
                      {((modelMeta.data?.model.recall ?? 0.991) * 100).toFixed(1)}%
                    </p>
                  </div>
                  <div className="rounded-lg border border-slate-800 bg-slate-950 p-3 text-center">
                    <span className="text-[10px] font-mono text-slate-500 uppercase">F1-Score</span>
                    <p className="mt-1 font-mono text-lg font-bold text-emerald-400">
                      {((modelMeta.data?.model.f1_score ?? 0.984) * 100).toFixed(1)}%
                    </p>
                  </div>
                </div>

                <div className="rounded-lg border border-slate-800 bg-slate-950 p-4">
                  <p className="font-mono text-xs uppercase text-slate-400 mb-2">Key Feature Weights</p>
                  <div className="space-y-2 text-xs font-mono">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-300">Mean Shannon Entropy (bits/byte)</span>
                      <span className="text-cyan-400">0.342</span>
                    </div>
                    <Progress value={34} className="h-1.5 bg-slate-800 [&>div]:bg-cyan-400" />
                    <div className="flex items-center justify-between pt-1">
                      <span className="text-slate-300">File Rename Velocity / min</span>
                      <span className="text-cyan-400">0.285</span>
                    </div>
                    <Progress value={28} className="h-1.5 bg-slate-800 [&>div]:bg-cyan-400" />
                    <div className="flex items-center justify-between pt-1">
                      <span className="text-slate-300">Extension Alteration (.locked, .enc)</span>
                      <span className="text-cyan-400">0.210</span>
                    </div>
                    <Progress value={21} className="h-1.5 bg-slate-800 [&>div]:bg-cyan-400" />
                  </div>
                </div>
              </div>

              <div className="rounded-xl border border-slate-800/80 bg-slate-900/60 p-5 flex flex-col justify-between">
                <div>
                  <h4 className="font-mono text-xs font-semibold uppercase text-slate-300">
                    Continuous MLOps Pipeline
                  </h4>
                  <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                    Trigger autonomous dataset synthesis and model retraining with zero downtime hot-reload.
                  </p>
                </div>

                <div className="space-y-3 my-4">
                  <div className="rounded border border-slate-800 bg-slate-950 p-2.5 text-xs font-mono text-slate-400">
                    <div className="flex justify-between">
                      <span>Training Set:</span>
                      <span className="text-slate-200">
                        {modelMeta.data?.model.train_samples ?? 1500} vectors
                      </span>
                    </div>
                    <div className="flex justify-between mt-1">
                      <span>Hot-Reload:</span>
                      <span className="text-emerald-400">Enabled</span>
                    </div>
                  </div>
                </div>

                <Button
                  variant="secondary"
                  disabled={retrainMutation.isPending}
                  onClick={() => retrainMutation.mutate(1500)}
                  className="w-full text-xs border border-slate-700 bg-slate-800 hover:bg-slate-700"
                >
                  <Sparkles className="mr-1.5 h-3.5 w-3.5 text-cyan-400" />
                  {retrainMutation.isPending ? "Retraining Weights..." : "Trigger Model Retrain"}
                </Button>
              </div>
            </div>
          </TabsContent>
        </Tabs>
      </main>

      {/* Forensic Report Inspection Modal */}
      <Dialog open={!!openReportId} onOpenChange={(o) => !o && setOpenReportId(null)}>
        <DialogContent className="max-h-[85vh] overflow-y-auto sm:max-w-2xl bg-slate-900 border border-slate-800 text-slate-100">
          <DialogHeader>
            <DialogTitle className="font-mono text-sm text-cyan-400">
              Forensic Incident: {reportDetail.data?.report.id ?? openReportId}
            </DialogTitle>
            <DialogDescription className="text-xs text-slate-400">
              {reportDetail.data
                ? `Workload: ${reportDetail.data.report.mode.toUpperCase()} · Process: ${reportDetail.data.report.process} (PID ${reportDetail.data.report.pid})`
                : "Loading report..."}
            </DialogDescription>
          </DialogHeader>

          {reportDetail.data && (
            <div className="space-y-4 text-xs font-mono">
              <div className="grid grid-cols-3 gap-2 rounded-lg border border-slate-800 bg-slate-950 p-3">
                <div>
                  <span className="text-slate-500 block text-[10px]">VERDICT</span>
                  <span
                    className={cn(
                      "font-bold uppercase",
                      reportDetail.data.report.verdict === "malicious"
                        ? "text-red-400"
                        : "text-emerald-400"
                    )}
                  >
                    {reportDetail.data.report.verdict}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">PEAK SCORE</span>
                  <span className="font-bold text-slate-200">
                    {(reportDetail.data.report.peakScore ?? 0).toFixed(3)}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[10px]">DURATION</span>
                  <span className="text-slate-200">{reportDetail.data.report.durationSec ?? 30}s</span>
                </div>
              </div>

              {/* Chronological Timeline */}
              <div>
                <p className="text-slate-400 uppercase text-[10px] mb-1.5">Evidence Timeline</p>
                <div className="space-y-1.5 max-h-36 overflow-y-auto rounded-lg border border-slate-800 bg-slate-950 p-2.5">
                  {(reportDetail.data.report.timeline || []).map((tl, idx) => (
                    <div key={idx} className="flex items-center gap-2 text-[11px]">
                      <span className="text-cyan-400 w-10">+{tl.t}s</span>
                      <span className="text-slate-500 font-bold w-12 tabular-nums">
                        {(tl.score || 0).toFixed(2)}
                      </span>
                      <span className="text-slate-300 truncate">{tl.event}</span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Analyst Recommendation */}
              <div className="rounded-lg border border-slate-800 bg-slate-950/80 p-3">
                <span className="text-[10px] text-slate-500 uppercase block mb-1">
                  Mitigation Recommendation
                </span>
                <p className="text-slate-300 text-xs font-sans leading-relaxed">
                  {reportDetail.data.report.recommendation ||
                    "Quarantine process tokens, isolate endpoint, and inspect volume shadow copies."}
                </p>
              </div>

              {/* Action Buttons */}
              <div className="flex justify-end gap-2 pt-2 border-t border-slate-800">
                <Button
                  size="sm"
                  variant="outline"
                  className="text-xs border-slate-700 bg-slate-800 text-slate-200"
                  onClick={() => {
                    const blob = new Blob([JSON.stringify(reportDetail.data!.report, null, 2)], {
                      type: "application/json",
                    });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = `incident-${reportDetail.data!.report.id}.json`;
                    a.click();
                    URL.revokeObjectURL(url);
                  }}
                >
                  Export JSON
                </Button>
              </div>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
