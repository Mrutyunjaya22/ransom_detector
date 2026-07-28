"""
Trains the RandomForestClassifier used by core.engine.MLScorer.

Real deployments would train on labeled telemetry from EDR datasets
(e.g. captured benign workloads + detonated ransomware samples in a
sandbox). For this prototype we generate synthetic feature vectors
whose distributions are grounded in published ransomware-behavior
characteristics (near-1.0 output entropy, high file-touch rates,
mass extension renames) versus normal desktop/office workloads, so the
full pipeline -- rule engine + ML scorer -- is testable end-to-end.
"""

import pickle

import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report

from core.engine import FEATURE_NAMES

RNG = np.random.default_rng(42)
N_PER_CLASS = 2000


def gen_benign(n):
    return np.column_stack([
        RNG.gamma(shape=2.0, scale=0.4, size=n),          # file_op_rate: low
        RNG.normal(4.2, 1.0, n).clip(0, 8),                # mean_entropy: mixed doc/text content
        RNG.beta(1, 12, n),                                 # high_entropy_fraction: rare
        RNG.gamma(shape=1.0, scale=0.2, size=n),           # ext_change_rate: rare
        np.zeros(n),                                        # suspicious_ext_rate: none
        RNG.normal(8, 6, n).clip(0, 100),                   # cpu_percent
        RNG.poisson(0.2, n),                                # children_spawned
        RNG.gamma(shape=2.0, scale=20000, size=n),          # io_bytes_per_s
        RNG.poisson(3, n) + 1,                              # touched_file_count
    ])


def gen_ransomware(n):
    return np.column_stack([
        RNG.gamma(shape=6.0, scale=1.5, size=n) + 3,        # file_op_rate: high
        RNG.normal(7.7, 0.25, n).clip(0, 8),                 # mean_entropy: near-max
        RNG.beta(10, 2, n),                                  # high_entropy_fraction: high
        RNG.gamma(shape=5.0, scale=1.0, size=n) + 1,        # ext_change_rate: high
        RNG.gamma(shape=3.0, scale=0.8, size=n),            # suspicious_ext_rate
        RNG.normal(55, 20, n).clip(0, 100),                 # cpu_percent
        RNG.poisson(1.5, n),                                 # children_spawned
        RNG.gamma(shape=4.0, scale=150000, size=n),         # io_bytes_per_s
        RNG.poisson(40, n) + 5,                              # touched_file_count
    ])


def main():
    X_benign = gen_benign(N_PER_CLASS)
    X_ransom = gen_ransomware(N_PER_CLASS)
    X = np.vstack([X_benign, X_ransom])
    y = np.array([0] * N_PER_CLASS + [1] * N_PER_CLASS)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y
    )

    clf = RandomForestClassifier(
        n_estimators=200, max_depth=8, random_state=42, class_weight="balanced"
    )
    clf.fit(X_train, y_train)

    y_pred = clf.predict(X_test)
    print("Feature order:", FEATURE_NAMES)
    print(classification_report(y_test, y_pred, target_names=["benign", "ransomware-like"]))

    importances = sorted(zip(FEATURE_NAMES, clf.feature_importances_), key=lambda t: -t[1])
    print("\nFeature importances:")
    for name, imp in importances:
        print(f"  {name:25s} {imp:.3f}")

    with open("models/rf_classifier.pkl", "wb") as f:
        pickle.dump(clf, f)
    print("\nSaved model to models/rf_classifier.pkl")


if __name__ == "__main__":
    main()
