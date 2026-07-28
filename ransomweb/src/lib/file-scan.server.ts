// Static file scoring for the detection prototype.
// Computes real features from the uploaded bytes and runs them through the
// same weighted scoring the runtime model uses.

export interface ScanResult {
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

const SUSPICIOUS_EXT = new Set([
  "lkd", "locked", "encrypted", "crypt", "crypto", "wncry", "wcry",
  "cerber", "locky", "zepto", "odin", "ryuk", "conti",
]);

const EXECUTABLE_EXT = new Set(["exe", "dll", "scr", "js", "vbs", "ps1", "bat", "cmd", "jar"]);

const RANSOM_NOTE_HINTS = [
  "your files have been encrypted",
  "bitcoin",
  "decrypt",
  "ransom",
  "tor browser",
  "recovery key",
  "vssadmin",
  "shadow copies",
];

function shannonEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const freq = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
  let h = 0;
  for (let i = 0; i < 256; i++) {
    if (!freq[i]) continue;
    const p = freq[i] / bytes.length;
    h -= p * Math.log2(p);
  }
  return h;
}

function detectMagic(bytes: Uint8Array): string {
  const b = Array.from(bytes.slice(0, 8));
  const starts = (sig: number[]) => sig.every((v, i) => b[i] === v);
  if (starts([0x4d, 0x5a])) return "pe-executable";
  if (starts([0x7f, 0x45, 0x4c, 0x46])) return "elf-executable";
  if (starts([0x50, 0x4b, 0x03, 0x04])) return "zip-archive";
  if (starts([0x25, 0x50, 0x44, 0x46])) return "pdf";
  if (starts([0x89, 0x50, 0x4e, 0x47])) return "png";
  if (starts([0xff, 0xd8, 0xff])) return "jpeg";
  return "unknown";
}

function printableRatio(bytes: Uint8Array): number {
  if (!bytes.length) return 0;
  let printable = 0;
  const sample = bytes.slice(0, 8192);
  for (let i = 0; i < sample.length; i++) {
    const c = sample[i];
    if (c === 9 || c === 10 || c === 13 || (c >= 32 && c <= 126)) printable++;
  }
  return printable / sample.length;
}

export function scanFile(fileName: string, bytes: Uint8Array): ScanResult {
  const ext = (fileName.split(".").pop() ?? "").toLowerCase();
  const entropy = shannonEntropy(bytes);
  const magic = detectMagic(bytes);
  const printable = printableRatio(bytes);
  const text =
    printable > 0.85
      ? new TextDecoder("utf-8", { fatal: false })
          .decode(bytes.slice(0, 16384))
          .toLowerCase()
      : "";
  const noteHits = RANSOM_NOTE_HINTS.filter((h) => text.includes(h));

  const reasons: string[] = [];
  let score = 0.04;

  const compressedFormat = magic === "zip-archive" || magic === "png" || magic === "jpeg";

  if (entropy > 7.8 && !compressedFormat) {
    score += 0.45;
    reasons.push(`Very high Shannon entropy (${entropy.toFixed(2)}/8.00) — consistent with encrypted payload`);
  } else if (entropy > 7.2 && !compressedFormat) {
    score += 0.22;
    reasons.push(`Elevated entropy (${entropy.toFixed(2)}/8.00) — packed or compressed content`);
  } else {
    reasons.push(`Entropy ${entropy.toFixed(2)}/8.00 within normal range`);
  }

  if (SUSPICIOUS_EXT.has(ext)) {
    score += 0.4;
    reasons.push(`Extension ".${ext}" matches known ransomware family marker`);
  }

  if (EXECUTABLE_EXT.has(ext) || magic === "pe-executable" || magic === "elf-executable") {
    score += 0.18;
    reasons.push(`Executable content detected (${magic !== "unknown" ? magic : ext})`);
  }

  if (noteHits.length >= 4) {
    score += 0.72;
    reasons.push(`Ransom-note template detected: ${noteHits.slice(0, 4).join(", ")}`);
  } else if (noteHits.length >= 2) {
    score += 0.45;
    reasons.push(`Ransom-note language detected: ${noteHits.slice(0, 3).join(", ")}`);
  } else if (noteHits.length === 1) {
    score += 0.12;
    reasons.push(`Possible ransom-note keyword: ${noteHits[0]}`);
  }

  if (magic === "unknown" && entropy > 7.5 && ext && !SUSPICIOUS_EXT.has(ext)) {
    score += 0.1;
    reasons.push("No recognisable file header despite known extension — header may be overwritten");
  }

  if (bytes.length === 0) {
    reasons.push("File is empty — nothing to analyse");
  }

  score = Math.max(0.01, Math.min(0.99, score));
  const verdict: ScanResult["verdict"] =
    score > 0.75 ? "malicious" : score > 0.45 ? "suspicious" : "clean";

  return {
    id: Math.random().toString(36).slice(2, 10),
    fileName,
    sizeBytes: bytes.length,
    entropy: Number(entropy.toFixed(3)),
    score: Number(score.toFixed(3)),
    verdict,
    reasons,
    features: {
      entropy: Number(entropy.toFixed(3)),
      printable_ratio: Number(printable.toFixed(3)),
      size_kb: Number((bytes.length / 1024).toFixed(2)),
      note_keyword_hits: noteHits.length,
      executable: EXECUTABLE_EXT.has(ext) || magic.includes("executable") ? 1 : 0,
      known_bad_extension: SUSPICIOUS_EXT.has(ext) ? 1 : 0,
    },
    scannedAt: new Date().toISOString(),
  };
}