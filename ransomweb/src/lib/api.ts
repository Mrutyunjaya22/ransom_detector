export interface StatusResponse {
  pipeline: {
    healthy: boolean;
    stage: string;
    mode: "idle" | "benign" | "attack";
    uptimeSec: number;
    eventsProcessed: number;
  };
  modelLoaded: boolean;
  collectorActive: boolean;
  monitoredProcess: { name: string; pid: number };
  riskScore: number;
  threshold: number;
  alertCount: number;
  analysis: {
    currentStage: string;
    activeStages: Array<{ name: string; status: "complete" | "active" | "pending"; detail: string }>;
    evidence: Array<{
      timestamp: number;
      stage: string;
      title: string;
      detail: string;
      severity: "low" | "medium" | "high" | "critical";
      signals: string[];
      features: Record<string, number>;
    }>;
    summary: {
      riskScore: number;
      ruleScore: number;
      mlScore: number;
      eventsProcessed: number;
      suspiciousSignals: number;
      forensicReady: boolean;
    };
  };
}

export interface AlertItem {
  id: string;
  severity: "low" | "medium" | "high" | "critical";
  process: string;
  pid: number;
  score: number;
  reasons: string[];
  createdAt: string;
}

export interface ReportItem {
  id: string;
  mode: string;
  verdict: "clean" | "suspicious" | "malicious";
  peakScore: number;
  alertCount: number;
  createdAt: string;
  process: string;
}

import { backendGet, backendPost } from "./backend-proxy";

export interface ReportDetailItem extends ReportItem {
  pid: number;
  durationSec: number;
  features: Record<string, number>;
  timeline: { t: number; score: number; event: string }[];
  alerts: AlertItem[];
  recommendation: string;
}

async function get<T>(url: string): Promise<T> {
  return backendGet(url);
}

async function post<T>(url: string, body: unknown): Promise<T> {
  return backendPost(url, body);
}

export const fetchStatus = () => get<StatusResponse>("/api/status");
export const fetchAlerts = () => get<{ alerts: AlertItem[]; count: number }>("/api/alerts");
export const fetchReports = () => get<{ reports: ReportItem[] }>("/api/reports");
export const fetchReport = (id: string) =>
  get<{ report: ReportDetailItem }>(`/api/reports/${id}`);

export async function startRun(mode: "benign" | "attack") {
  return post("/api/run", { mode });
}

export interface ScanResultItem {
  id: string;
  fileName: string;
  sizeBytes: number;
  entropy: number;
  score: number;
  verdict: "clean" | "suspicious" | "malicious";
  reasons: string[];
  features: Record<string, number>;
  scannedAt: string;
}

export const fetchScans = () => get<{ scans: ScanResultItem[] }>("/api/scan");

export interface AiAnalysis {
  summary: string;
  likelyFamily: string;
  confidence: number;
  mitre: string[];
  actions: string[];
  falsePositiveRisk: "low" | "medium" | "high";
}

export async function analyzeWithModel(input: {
  kind: "file" | "report";
  subject: string;
  score: number;
  verdict: string;
  reasons: string[];
  features: Record<string, number>;
}) {
  return post<{ analysis: AiAnalysis }>("/api/analyze", input).then((data) => data.analysis);
}

export async function scanFile(file: File) {
  const body = new FormData();
  body.append("file", file);
  const backendUrl = import.meta.env.VITE_API_BASE_URL ?? "http://127.0.0.1:8000";
  const res = await fetch(`${backendUrl}/api/scan`, {
    method: "POST",
    body,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(`Scan failed: ${res.status} ${text}`);
  }
  const json = (await res.json()) as { scan: ScanResultItem };
  return json.scan;
}