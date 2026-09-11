import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import {
  FileSearch,
  UploadCloud,
  FileCheck2,
  FileWarning,
  Sparkles,
  Download,
  CheckCircle2,
  AlertOctagon,
  FileText,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Badge } from "@/components/ui/badge";
import {
  analyzeWithModel,
  fetchScans,
  scanFile,
  type AiAnalysis,
  type ScanResultItem,
} from "@/lib/api";
import { cn } from "@/lib/utils";

function verdictBadgeClass(v: ScanResultItem["verdict"]) {
  switch (v) {
    case "malicious":
      return "border-red-500/50 bg-red-500/15 text-red-400";
    case "suspicious":
      return "border-amber-500/50 bg-amber-500/15 text-amber-400";
    default:
      return "border-emerald-500/50 bg-emerald-500/15 text-emerald-400";
  }
}

function downloadReport(result: ScanResultItem, analysis: AiAnalysis | null) {
  const blob = new Blob([JSON.stringify({ scan: result, aiTriage: analysis }, null, 2)], {
    type: "application/json",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `scan-${result.fileName}-${result.id}.json`;
  a.click();
  URL.revokeObjectURL(url);
}

export function FileScanner() {
  const qc = useQueryClient();
  const inputRef = useRef<HTMLInputElement>(null);
  const [dragging, setDragging] = useState(false);
  const [current, setCurrent] = useState<ScanResultItem | null>(null);
  const [batch, setBatch] = useState<ScanResultItem[]>([]);
  const [analysis, setAnalysis] = useState<AiAnalysis | null>(null);
  const [autoTriage, setAutoTriage] = useState(true);

  const history = useQuery({ queryKey: ["scans"], queryFn: fetchScans });

  const triage = useMutation({
    mutationFn: (r: ScanResultItem) =>
      analyzeWithModel({
        kind: "file",
        subject: r.fileName,
        score: r.score,
        verdict: r.verdict,
        reasons: r.reasons,
        features: r.features,
      }),
    onSuccess: setAnalysis,
  });

  const scan = useMutation({
    mutationFn: async (files: File[]) => {
      const out: ScanResultItem[] = [];
      for (const f of files) out.push(await scanFile(f));
      return out;
    },
    onSuccess: (results) => {
      setBatch(results);
      const worst = [...results].sort((a, b) => b.score - a.score)[0];
      select(worst);
      qc.invalidateQueries({ queryKey: ["scans"] });
    },
  });

  const select = (result: ScanResultItem) => {
    setCurrent(result);
    setAnalysis(null);
    triage.reset();
    if (autoTriage) triage.mutate(result);
  };

  const handleFiles = (files: FileList | null) => {
    const list = files ? Array.from(files) : [];
    if (list.length) scan.mutate(list);
  };

  // One-click quick demo sample generator
  const triggerSampleTest = (type: "clean" | "encrypted") => {
    if (type === "clean") {
      const content =
        "CONFIDENTIAL AUDIT REPORT 2026\nQuarterly financial records indicate normal operating activity.\nNo anomalies detected.\nStatus: Approved.\n";
      const file = new File([content], "clean_audit_report.txt", { type: "text/plain" });
      scan.mutate([file]);
    } else {
      // High-entropy pseudorandom buffer
      const randomBytes = new Uint8Array(8192);
      window.crypto.getRandomValues(randomBytes);
      const file = new File([randomBytes], "financial_database.xlsx.locked", {
        type: "application/octet-stream",
      });
      scan.mutate([file]);
    }
  };

  return (
    <div className="space-y-4">
      {/* Drag & Drop Zone */}
      <div
        onDragOver={(e) => {
          e.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(e) => {
          e.preventDefault();
          setDragging(false);
          handleFiles(e.dataTransfer.files);
        }}
        className={cn(
          "rounded-xl border border-dashed p-6 text-center transition-all bg-slate-950/60",
          dragging ? "border-cyan-400 bg-cyan-500/10" : "border-slate-800 hover:border-slate-700"
        )}
      >
        <UploadCloud className="mx-auto h-8 w-8 text-cyan-400 mb-2 opacity-80" />
        <p className="text-sm font-medium text-slate-200">
          Drop files here or browse to inspect Shannon entropy & ransomware vectors
        </p>
        <p className="mt-1 font-mono text-xs text-slate-500">
          Supports binary payloads, office docs, archives up to 50 MB
        </p>

        <input
          ref={inputRef}
          type="file"
          multiple
          className="hidden"
          onChange={(e) => handleFiles(e.target.files)}
        />

        {/* Buttons: File Picker & Quick Sample Buttons */}
        <div className="mt-4 flex flex-wrap items-center justify-center gap-2.5">
          <Button
            size="sm"
            variant="secondary"
            disabled={scan.isPending}
            onClick={() => inputRef.current?.click()}
            className="h-8 border border-slate-700 bg-slate-800 text-xs text-slate-100 hover:bg-slate-700 cursor-pointer"
          >
            <FileSearch className="mr-1.5 h-3.5 w-3.5 text-cyan-400" />
            {scan.isPending ? "Analyzing..." : "Choose Files from Disk"}
          </Button>

          <Button
            size="sm"
            variant="outline"
            disabled={scan.isPending}
            onClick={() => triggerSampleTest("clean")}
            className="h-8 border-emerald-500/30 bg-emerald-500/10 text-xs text-emerald-400 hover:bg-emerald-500/20 cursor-pointer"
          >
            <FileCheck2 className="mr-1.5 h-3.5 w-3.5" />
            Test Clean Sample
          </Button>

          <Button
            size="sm"
            variant="outline"
            disabled={scan.isPending}
            onClick={() => triggerSampleTest("encrypted")}
            className="h-8 border-red-500/30 bg-red-500/10 text-xs text-red-400 hover:bg-red-500/20 cursor-pointer"
          >
            <FileWarning className="mr-1.5 h-3.5 w-3.5" />
            Test Encrypted Ransomware
          </Button>
        </div>
      </div>

      {scan.isError && (
        <div className="rounded-lg border border-red-500/50 bg-red-500/10 p-3 text-xs text-red-300">
          {(scan.error as Error).message}
        </div>
      )}

      {/* Batch Results List */}
      {batch.length > 1 && (
        <div className="rounded-lg border border-slate-800 bg-slate-950 p-3">
          <p className="mb-2 font-mono text-[11px] uppercase tracking-wider text-slate-400">
            Batch Scanned Files ({batch.length})
          </p>
          <ul className="space-y-1 font-mono text-xs">
            {batch.map((b) => (
              <li key={b.id}>
                <button
                  onClick={() => select(b)}
                  className={cn(
                    "flex w-full items-center justify-between rounded px-2.5 py-1.5 text-left transition-colors cursor-pointer",
                    current?.id === b.id ? "bg-slate-800 text-cyan-400" : "hover:bg-slate-800/50 text-slate-300"
                  )}
                >
                  <span className="truncate">{b.fileName}</span>
                  <span className="flex items-center gap-3">
                    <span className="tabular-nums">Score: {b.score.toFixed(3)}</span>
                    <Badge variant="outline" className={cn("text-[10px]", verdictBadgeClass(b.verdict))}>
                      {b.verdict}
                    </Badge>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {/* Active Selected Scan Detail */}
      {current && (
        <div className="rounded-xl border border-slate-800 bg-slate-950/80 p-5 space-y-4">
          <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800/80 pb-3">
            <div className="flex items-center gap-2">
              <FileText className="h-4 w-4 text-cyan-400" />
              <span className="font-mono text-sm font-semibold text-slate-200">
                {current.fileName}
              </span>
              <span className="font-mono text-xs text-slate-500">
                ({(current.sizeBytes / 1024).toFixed(1)} KB)
              </span>
            </div>
            <Badge variant="outline" className={cn("font-mono text-xs font-bold uppercase", verdictBadgeClass(current.verdict))}>
              VERDICT: {current.verdict}
            </Badge>
          </div>

          {/* Metric Cards Grid */}
          <div className="grid grid-cols-3 gap-3 font-mono text-xs">
            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
              <span className="text-slate-500 block text-[10px] uppercase">Threat Score</span>
              <span
                className={cn(
                  "font-bold text-xl",
                  current.verdict === "malicious"
                    ? "text-red-400"
                    : current.verdict === "suspicious"
                    ? "text-amber-400"
                    : "text-emerald-400"
                )}
              >
                {current.score.toFixed(3)}
              </span>
              <span className="text-[10px] text-slate-500 block mt-0.5">/ 1.000 limit</span>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
              <span className="text-slate-500 block text-[10px] uppercase">Shannon Entropy</span>
              <span
                className={cn(
                  "font-bold text-xl",
                  current.entropy >= 7.5
                    ? "text-red-400"
                    : current.entropy >= 7.0
                    ? "text-amber-400"
                    : "text-emerald-400"
                )}
              >
                {current.entropy.toFixed(3)}
              </span>
              <span className="text-[10px] text-slate-500 block mt-0.5">bits / byte (max 8.00)</span>
            </div>

            <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3">
              <span className="text-slate-500 block text-[10px] uppercase">Magic Byte Header</span>
              <span className="font-bold text-sm text-slate-200 truncate block mt-1">
                {current.features.detectedMimeOrMagic || "Raw Stream"}
              </span>
              <span className="text-[10px] text-slate-500 block">Header verification</span>
            </div>
          </div>

          {/* Entropy Progress Bar */}
          <div>
            <div className="flex justify-between font-mono text-[10px] text-slate-500 mb-1">
              <span>Plaintext (0.0 - 4.5)</span>
              <span>Compressed (5.0 - 7.2)</span>
              <span className="text-red-400">Encrypted (&gt; 7.5)</span>
            </div>
            <Progress
              value={(current.entropy / 8.0) * 100}
              className={cn(
                "h-2 bg-slate-800",
                current.entropy >= 7.5
                  ? "[&>div]:bg-red-500"
                  : current.entropy >= 6.8
                  ? "[&>div]:bg-amber-400"
                  : "[&>div]:bg-emerald-400"
              )}
            />
          </div>

          {/* Reasoning Checklist */}
          <div>
            <span className="text-[11px] font-mono uppercase text-slate-400 block mb-1.5">
              Behavioral &amp; Structural Reasons
            </span>
            <ul className="space-y-1 text-xs">
              {current.reasons.map((r, idx) => (
                <li key={idx} className="flex items-start gap-1.5 text-slate-300">
                  <span className="text-cyan-400 font-bold">›</span>
                  <span>{r}</span>
                </li>
              ))}
            </ul>
          </div>

          {/* Actions & AI Triage */}
          <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-slate-800/80">
            <Button
              size="sm"
              variant="secondary"
              disabled={triage.isPending}
              onClick={() => triage.mutate(current)}
              className="h-8 text-xs border border-slate-700 bg-slate-800 text-slate-200 hover:bg-slate-700"
            >
              <Sparkles className="mr-1.5 h-3.5 w-3.5 text-cyan-400" />
              {triage.isPending ? "Analyzing MITRE ATT&CK..." : "Run AI Threat Triage"}
            </Button>

            <Button
              size="sm"
              variant="outline"
              onClick={() => downloadReport(current, analysis)}
              className="h-8 text-xs border-slate-800 bg-slate-900 text-slate-300 hover:bg-slate-800"
            >
              <Download className="mr-1.5 h-3.5 w-3.5" />
              Export JSON
            </Button>
          </div>

          {/* Automated AI Triage Box */}
          {analysis && (
            <div className="rounded-lg border border-cyan-500/30 bg-cyan-500/5 p-4 space-y-3">
              <div className="flex items-center justify-between">
                <span className="font-mono text-xs font-bold uppercase tracking-wider text-cyan-400">
                  AI Threat Classification: {analysis.likelyFamily}
                </span>
                <Badge variant="outline" className="font-mono text-[10px] text-slate-400">
                  Confidence {(analysis.confidence * 100).toFixed(0)}% · FP Risk: {analysis.falsePositiveRisk}
                </Badge>
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">{analysis.summary}</p>
              {analysis.mitre.length > 0 && (
                <div className="flex flex-wrap gap-1.5">
                  {analysis.mitre.map((m) => (
                    <Badge key={m} variant="outline" className="font-mono text-[10px] border-slate-700 text-slate-300">
                      {m}
                    </Badge>
                  ))}
                </div>
              )}
              {analysis.actions.length > 0 && (
                <div className="border-t border-slate-800/60 pt-2">
                  <span className="font-mono text-[10px] uppercase text-slate-400 block mb-1">
                    Prescribed SOC Containment Actions
                  </span>
                  <ul className="space-y-1 text-xs text-slate-300">
                    {analysis.actions.map((act, i) => (
                      <li key={i} className="flex items-center gap-1.5">
                        <CheckCircle2 className="h-3 w-3 text-emerald-400 shrink-0" />
                        <span>{act}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* Historical Scans */}
      {!!history.data?.scans.length && (
        <div className="rounded-lg border border-slate-800/80 bg-slate-950 p-4">
          <p className="mb-2 font-mono text-[11px] uppercase tracking-wider text-slate-400">
            Recent Scanned Artifacts
          </p>
          <ul className="divide-y divide-slate-800/60 font-mono text-xs">
            {history.data.scans.slice(0, 8).map((sc) => (
              <li key={sc.id}>
                <button
                  onClick={() => select(sc)}
                  className="flex w-full items-center justify-between py-2 text-left hover:text-cyan-400 transition-colors cursor-pointer"
                >
                  <span className="truncate max-w-[260px] text-slate-300">{sc.fileName}</span>
                  <span className="flex items-center gap-3">
                    <span className="tabular-nums text-slate-400">Entropy: {sc.entropy.toFixed(2)}</span>
                    <Badge variant="outline" className={cn("text-[10px]", verdictBadgeClass(sc.verdict))}>
                      {sc.verdict}
                    </Badge>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}
    </div>
  );
}
