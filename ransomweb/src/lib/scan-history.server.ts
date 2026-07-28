import type { ScanResult } from "./file-scan.server";

const g = globalThis as unknown as { __rdScans?: ScanResult[] };

export function getScanHistory(): ScanResult[] {
  if (!g.__rdScans) g.__rdScans = [];
  return g.__rdScans;
}

export function recordScan(scan: ScanResult) {
  const list = getScanHistory();
  list.unshift(scan);
  g.__rdScans = list.slice(0, 10);
  return scan;
}