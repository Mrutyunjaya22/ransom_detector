// In-memory simulation of the ransomware detection pipeline.
// Swap these internals for real collector/model calls when the Python
// detection pipeline is wired in.

export type Mode = "idle" | "benign" | "attack";

export interface Alert {
  id: string;
  severity: "low" | "medium" | "high" | "critical";
  process: string;
  pid: number;
  score: number;
  reasons: string[];
  createdAt: string;
}

export interface ReportSummary {
  id: string;
  mode: Mode;
  verdict: "clean" | "suspicious" | "malicious";
  peakScore: number;
  alertCount: number;
  createdAt: string;
}

export interface ReportDetail extends ReportSummary {
  process: string;
  pid: number;
  durationSec: number;
  features: Record<string, number>;
  timeline: { t: number; score: number; event: string }[];
  alerts: Alert[];
  recommendation: string;
}

interface State {
  startedAt: number;
  mode: Mode;
  runStartedAt: number | null;
  stage: string;
  score: number;
  process: { name: string; pid: number };
  alerts: Alert[];
  reports: ReportDetail[];
  eventsProcessed: number;
  modelLoaded: boolean;
  collectorActive: boolean;
}

const g = globalThis as unknown as { __rdPipeline?: State };

const STAGES = [
  "idle",
  "collecting",
  "feature-extraction",
  "scoring",
  "correlating",
  "reporting",
] as const;

const BENIGN_REASONS = [
  "Normal file read/write ratio",
  "Entropy within baseline",
  "Known-good signing certificate",
];

const ATTACK_REASONS = [
  "High-entropy writes across 412 files/min",
  "Mass file rename to unknown extension (.lkd)",
  "Shadow copy deletion via vssadmin",
  "Rapid directory traversal in user documents",
  "Outbound connection to unrated host",
  "Registry run-key persistence added",
];

function rid() {
  return Math.random().toString(36).slice(2, 10);
}

function makeAlert(mode: Mode, score: number, process: string, pid: number): Alert {
  const pool = mode === "attack" ? ATTACK_REASONS : BENIGN_REASONS;
  const count = mode === "attack" ? 3 : 1;
  const reasons = [...pool].sort(() => Math.random() - 0.5).slice(0, count);
  const severity: Alert["severity"] =
    score > 0.9 ? "critical" : score > 0.7 ? "high" : score > 0.45 ? "medium" : "low";
  return {
    id: rid(),
    severity,
    process,
    pid,
    score: Number(score.toFixed(3)),
    reasons,
    createdAt: new Date().toISOString(),
  };
}

function buildReport(mode: Mode, at: number): ReportDetail {
  const attack = mode === "attack";
  const process = attack ? "enc_worker.exe" : "backup_agent.exe";
  const pid = attack ? 7714 : 3311;
  const alerts = attack
    ? [makeAlert("attack", 0.93, process, pid), makeAlert("attack", 0.71, process, pid)]
    : [];
  return {
    id: rid(),
    mode,
    verdict: attack ? "malicious" : "clean",
    peakScore: attack ? 0.93 : 0.18,
    alertCount: alerts.length,
    createdAt: new Date(at).toISOString(),
    process,
    pid,
    durationSec: attack ? 42 : 60,
    features: {
      write_entropy: attack ? 7.94 : 4.12,
      files_touched_per_min: attack ? 412 : 27,
      rename_ratio: attack ? 0.88 : 0.03,
      crypto_api_calls: attack ? 1930 : 12,
      unique_extensions: attack ? 19 : 4,
    },
    timeline: [0, 10, 20, 30, 40].map((t, i) => ({
      t,
      score: attack ? Math.min(0.97, 0.1 + i * 0.22) : 0.08 + i * 0.02,
      event: attack
        ? ["process spawn", "bulk read", "entropy spike", "mass rename", "vssadmin delete"][i]
        : ["process spawn", "scheduled scan", "incremental copy", "checksum", "complete"][i],
    })),
    alerts,
    recommendation: attack
      ? "Isolate host, kill PID, restore from last known-good snapshot."
      : "No action required. Activity matches known backup baseline.",
  };
}

function seed(): State {
  const now = Date.now();
  return {
    startedAt: now,
    mode: "idle",
    runStartedAt: null,
    stage: "idle",
    score: 0.06,
    process: { name: "svc_indexer.exe", pid: 4821 },
    alerts: [],
    reports: [
      buildReport("attack", now - 1000 * 60 * 47),
      buildReport("benign", now - 1000 * 60 * 120),
    ],
    eventsProcessed: 18422,
    modelLoaded: true,
    collectorActive: true,
  };
}

export function getState(): State {
  if (!g.__rdPipeline) g.__rdPipeline = seed();
  return g.__rdPipeline;
}

export function finishRun() {
  const s = getState();
  if (s.mode === "idle") return s;
  const attack = s.mode === "attack";
  const report = buildReport(s.mode, Date.now());
  report.process = s.process.name;
  report.pid = s.process.pid;
  report.alerts = s.alerts.slice();
  report.alertCount = report.alerts.length;
  report.peakScore = Number(
    Math.max(s.score, ...report.alerts.map((a) => a.score), attack ? 0.9 : 0.15).toFixed(3),
  );
  report.verdict =
    report.peakScore > 0.75 ? "malicious" : report.peakScore > 0.45 ? "suspicious" : "clean";
  s.reports.unshift(report);
  s.reports = s.reports.slice(0, 15);
  s.mode = "idle";
  s.runStartedAt = null;
  s.stage = "idle";
  return s;
}

/** Advances the simulated run based on elapsed time. */
export function tick() {
  const s = getState();
  s.eventsProcessed += Math.floor(Math.random() * 40) + 5;

  if (s.mode === "idle" || s.runStartedAt === null) {
    s.stage = "idle";
    s.score = Math.max(0.02, s.score * 0.85);
    return s;
  }

  const elapsed = (Date.now() - s.runStartedAt) / 1000;
  const progress = Math.min(1, elapsed / 30);
  s.stage = STAGES[Math.min(STAGES.length - 1, 1 + Math.floor(progress * 4))];

  const target =
    s.mode === "attack" ? 0.12 + progress * 0.85 : 0.08 + Math.sin(elapsed / 4) * 0.04;
  s.score = Math.max(0.01, Math.min(0.99, target + (Math.random() - 0.5) * 0.04));

  const last = s.alerts[0];
  const cooldown = !last || Date.now() - Date.parse(last.createdAt) > 6000;
  if (s.score > 0.6 && cooldown) {
    s.alerts.unshift(makeAlert(s.mode, s.score, s.process.name, s.process.pid));
    s.alerts = s.alerts.slice(0, 12);
  }

  if (progress >= 1) finishRun();
  return s;
}

export function startRun(mode: "benign" | "attack") {
  const s = getState();
  s.mode = mode;
  s.runStartedAt = Date.now();
  s.stage = "collecting";
  s.score = 0.1;
  s.alerts = [];
  s.process =
    mode === "attack"
      ? { name: "enc_worker.exe", pid: 7000 + Math.floor(Math.random() * 900) }
      : { name: "backup_agent.exe", pid: 3000 + Math.floor(Math.random() * 900) };
  return s;
}

export function statusPayload() {
  const s = tick();
  return {
    pipeline: {
      healthy: s.modelLoaded && s.collectorActive,
      stage: s.stage,
      mode: s.mode,
      uptimeSec: Math.floor((Date.now() - s.startedAt) / 1000),
      eventsProcessed: s.eventsProcessed,
    },
    modelLoaded: s.modelLoaded,
    collectorActive: s.collectorActive,
    monitoredProcess: s.process,
    riskScore: Number(s.score.toFixed(3)),
    threshold: 0.6,
    alertCount: s.alerts.length,
  };
}