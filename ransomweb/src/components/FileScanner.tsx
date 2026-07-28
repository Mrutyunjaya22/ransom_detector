import { useRef, useState } from "react";
import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
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

function verdictClass(v: ScanResultItem["verdict"]) {
  return v === "malicious" ? "text-danger" : v === "suspicious" ? "text-warn" : "text-ok";
}

function download(result: ScanResultItem, analysis: AiAnalysis | null) {
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

  return (
    <div className="space-y-4">
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
          "rounded-md border border-dashed p-6 text-center transition-colors",
          dragging ? "border-primary bg-primary/10" : "border-border bg-surface/50",
        )}
      >
        <p className="text-sm text-muted-foreground">
          Drop one or more files here to score them with the detection model
        </p>
        <p className="mt-1 font-mono text-xs text-muted-foreground">max 8 MB per file</p>
        <input
          ref={inputRef}
          type="file"
          multiple
          className="hidden"
          onChange={(e) => handleFiles(e.target.files)}
        />
        <div className="mt-3 flex flex-wrap items-center justify-center gap-3">
          <Button
            variant="secondary"
            disabled={scan.isPending}
            onClick={() => inputRef.current?.click()}
          >
            {scan.isPending ? "Analysing…" : "Choose files"}
          </Button>
          <label className="flex cursor-pointer items-center gap-2 font-mono text-xs text-muted-foreground">
            <input
              type="checkbox"
              checked={autoTriage}
              onChange={(e) => setAutoTriage(e.target.checked)}
              className="accent-primary"
            />
            auto AI triage
          </label>
        </div>
      </div>

      {scan.isError && (
        <p className="rounded border border-danger/50 bg-danger/10 p-3 text-sm text-danger">
          {(scan.error as Error).message}
        </p>
      )}

      {batch.length > 1 && (
        <div className="rounded-md border border-border bg-surface/60 p-3">
          <p className="mb-2 font-mono text-xs uppercase tracking-wider text-muted-foreground">
            Batch results ({batch.length})
          </p>
          <ul className="space-y-1 font-mono text-xs">
            {batch.map((b) => (
              <li key={b.id}>
                <button
                  onClick={() => select(b)}
                  className={cn(
                    "flex w-full items-center justify-between rounded px-2 py-1 text-left hover:bg-primary/10",
                    current?.id === b.id && "bg-primary/10",
                  )}
                >
                  <span className="truncate">{b.fileName}</span>
                  <span className="flex items-center gap-3">
                    <span className="tabular-nums">{b.score.toFixed(3)}</span>
                    <span className={verdictClass(b.verdict)}>{b.verdict}</span>
                  </span>
                </button>
              </li>
            ))}
          </ul>
        </div>
      )}

      {current && (
        <div className="rounded-md border border-border bg-surface p-4">
          <div className="flex flex-wrap items-baseline justify-between gap-2">
            <p className="font-mono text-sm">{current.fileName}</p>
            <Badge
              variant="outline"
              className={cn("font-mono uppercase", verdictClass(current.verdict))}
            >
              {current.verdict}
            </Badge>
          </div>

          <p className="mt-3 font-mono text-3xl font-semibold tabular-nums">
            {current.score.toFixed(3)}
          </p>
          <Progress
            value={Math.round(current.score * 100)}
            className={cn(
              "mt-2 h-2",
              current.verdict === "malicious" && "[&>div]:bg-danger",
              current.verdict === "suspicious" && "[&>div]:bg-warn",
            )}
          />

          <ul className="mt-4 space-y-1 text-xs text-muted-foreground">
            {current.reasons.map((r) => (
              <li key={r}>— {r}</li>
            ))}
          </ul>

          <ul className="mt-4 grid grid-cols-2 gap-2 font-mono text-xs sm:grid-cols-3">
            {Object.entries(current.features).map(([k, v]) => (
              <li
                key={k}
                className="flex justify-between rounded border border-border px-2 py-1"
              >
                <span className="text-muted-foreground">{k}</span>
                <span className="tabular-nums">{v}</span>
              </li>
            ))}
          </ul>

          <div className="mt-4 flex flex-wrap gap-2">
            <Button
              size="sm"
              variant="secondary"
              disabled={triage.isPending}
              onClick={() => triage.mutate(current)}
            >
              {triage.isPending ? "Model reasoning…" : analysis ? "Re-run AI triage" : "Run AI triage"}
            </Button>
            <Button size="sm" variant="outline" onClick={() => download(current, analysis)}>
              Export JSON
            </Button>
          </div>

          {triage.isError && (
            <p className="mt-3 rounded border border-danger/50 bg-danger/10 p-2 text-xs text-danger">
              {(triage.error as Error).message}
            </p>
          )}

          {analysis && (
            <div className="mt-4 rounded-md border border-primary/40 bg-primary/5 p-3">
              <div className="flex flex-wrap items-center justify-between gap-2">
                <p className="font-mono text-xs uppercase tracking-wider text-primary">
                  AI triage · {analysis.likelyFamily}
                </p>
                <span className="font-mono text-xs text-muted-foreground">
                  confidence {(analysis.confidence * 100).toFixed(0)}% · FP risk{" "}
                  {analysis.falsePositiveRisk}
                </span>
              </div>
              <p className="mt-2 text-sm">{analysis.summary}</p>
              {!!analysis.mitre.length && (
                <div className="mt-3 flex flex-wrap gap-1">
                  {analysis.mitre.map((m) => (
                    <Badge key={m} variant="outline" className="font-mono text-[10px]">
                      {m}
                    </Badge>
                  ))}
                </div>
              )}
              {!!analysis.actions.length && (
                <ul className="mt-3 space-y-1 text-xs text-muted-foreground">
                  {analysis.actions.map((a) => (
                    <li key={a}>→ {a}</li>
                  ))}
                </ul>
              )}
            </div>
          )}
        </div>
      )}

      {!!history.data?.scans.length && (
        <div>
          <p className="mb-2 font-mono text-xs uppercase tracking-wider text-muted-foreground">
            Recent file scans
          </p>
          <ul className="divide-y divide-border/60 font-mono text-xs">
            {history.data.scans.map((s) => (
              <li key={s.id}>
                <button
                  onClick={() => select(s)}
                  className="flex w-full items-center justify-between py-2 text-left hover:text-primary"
                >
                  <span className="truncate">{s.fileName}</span>
                  <span className="flex items-center gap-4">
                    <span className="tabular-nums">{s.score.toFixed(3)}</span>
                    <span className={verdictClass(s.verdict)}>{s.verdict}</span>
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
