"""
Feature extraction layer.

Converts raw filesystem/process events into the numeric feature vector
consumed by the behavioral analysis engine:
  - Shannon entropy of file content (post-write)
  - file-operation rate per second
  - extension-change frequency
  - process-level features (handle count proxy, children spawned)
"""

import math
import os
from collections import Counter, defaultdict


def shannon_entropy(data: bytes) -> float:
    """Shannon entropy of a byte string, in bits/byte (0-8)."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy


def safe_read_entropy(path: str, max_bytes: int = 65536, retries: int = 3) -> float | None:
    """
    Read up to max_bytes from a file and compute entropy.

    Returns None (not 0.0) when the file cannot be read, e.g. because it
    was renamed/deleted between the event firing and the read happening.
    Callers must treat None as "no sample" and NOT let it pull an average
    toward zero -- this was the original bug: a race between rename events
    and reads was producing silent zero-entropy samples that diluted the
    running average and made the risk score understate real attacks.
    """
    for attempt in range(retries):
        try:
            with open(path, "rb") as f:
                data = f.read(max_bytes)
            if not data:
                return None
            return shannon_entropy(data)
        except (FileNotFoundError, PermissionError, OSError):
            continue
    return None


class ExtensionTracker:
    """Tracks extension-change events (e.g. .docx -> .locked) per process."""

    SUSPICIOUS_EXTENSIONS = {
        ".locked", ".encrypted", ".enc", ".crypt", ".crypted",
        ".ransom", ".locky", ".cerber", ".wcry", ".wncry", ".xyz",
    }

    def __init__(self):
        self.change_counts = defaultdict(int)   # pid -> count
        self.suspicious_counts = defaultdict(int)

    def record_rename(self, pid: int, src_path: str, dst_path: str):
        src_ext = os.path.splitext(src_path)[1].lower()
        dst_ext = os.path.splitext(dst_path)[1].lower()
        if src_ext != dst_ext:
            self.change_counts[pid] += 1
            if dst_ext in self.SUSPICIOUS_EXTENSIONS:
                self.suspicious_counts[pid] += 1

    def rate(self, pid: int, window_seconds: float) -> float:
        if window_seconds <= 0:
            return 0.0
        return self.change_counts.get(pid, 0) / window_seconds

    def suspicious_rate(self, pid: int, window_seconds: float) -> float:
        if window_seconds <= 0:
            return 0.0
        return self.suspicious_counts.get(pid, 0) / window_seconds


class LatestEntropyTracker:
    """
    Tracks the *latest* entropy sample per file path per process, rather
    than a running average of every sample seen. Ransomware rewrites the
    same set of files; averaging every intermediate read (including partial
    writes) dilutes the signal. What matters for detection is the final
    state of each touched file.
    """

    def __init__(self):
        # pid -> {path: entropy}
        self._latest = defaultdict(dict)

    def update(self, pid: int, path: str, entropy: float | None):
        if entropy is None:
            return
        self._latest[pid][path] = entropy

    def mean_entropy(self, pid: int) -> float:
        samples = self._latest.get(pid, {})
        if not samples:
            return 0.0
        return sum(samples.values()) / len(samples)

    def high_entropy_fraction(self, pid: int, threshold: float = 7.5) -> float:
        samples = self._latest.get(pid, {})
        if not samples:
            return 0.0
        high = sum(1 for v in samples.values() if v >= threshold)
        return high / len(samples)

    def touched_file_count(self, pid: int) -> int:
        return len(self._latest.get(pid, {}))
