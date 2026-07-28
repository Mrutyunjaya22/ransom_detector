"""
Test-harness workload generator.

Produces two kinds of file activity inside the sandbox directory so the
detection pipeline can be validated end-to-end:

  - benign_workload(): normal office-style edits (low entropy text,
    occasional saves, no mass renames)
  - attack_shaped_workload(): activity that matches the *feature
    signature* ransomware produces (rapid writes of high-entropy bytes,
    then extension renames to a locked-looking suffix) so the pipeline's
    entropy/rate/rename detectors can be exercised.

This is a benign test fixture -- it writes os.urandom() bytes to its own
throwaway sandbox files. It contains no encryption, no propagation, no
persistence, and does not touch anything outside test_sandbox/. Its only
purpose is to produce the same *measurable feature pattern* (entropy,
op-rate, rename pattern) that the detector is built to catch, so the
detector itself can be tested.
"""

import os
import random
import time


def benign_workload(sandbox_dir: str, duration: float = 5.0):
    os.makedirs(sandbox_dir, exist_ok=True)
    end = time.time() + duration
    i = 0
    words = ["report", "draft", "notes", "budget", "summary"]
    while time.time() < end:
        path = os.path.join(sandbox_dir, f"{random.choice(words)}_{i}.txt")
        with open(path, "w") as f:
            f.write("Quarterly notes: " + " ".join(random.choices(words, k=20)))
        i += 1
        time.sleep(random.uniform(0.4, 0.9))


def attack_shaped_workload(sandbox_dir: str, file_count: int = 25):
    """
    Writes high-entropy bytes to a batch of files then renames them with a
    ransom-style extension, in rapid succession -- matching the feature
    signature (entropy jump + mass rename in a short window) the pipeline
    is designed to detect.
    """
    os.makedirs(sandbox_dir, exist_ok=True)
    paths = []
    for i in range(file_count):
        path = os.path.join(sandbox_dir, f"victim_doc_{i}.docx")
        with open(path, "w") as f:
            f.write("Original benign document content " * 10)
        paths.append(path)
    time.sleep(0.3)

    for path in paths:
        with open(path, "wb") as f:
            f.write(os.urandom(4096))
        locked_path = path + ".locked"
        os.rename(path, locked_path)
        time.sleep(0.05)


if __name__ == "__main__":
    import sys
    mode = sys.argv[1] if len(sys.argv) > 1 else "benign"
    sandbox = sys.argv[2] if len(sys.argv) > 2 else "test_sandbox"
    if mode == "attack":
        attack_shaped_workload(sandbox)
    else:
        benign_workload(sandbox, duration=6.0)
