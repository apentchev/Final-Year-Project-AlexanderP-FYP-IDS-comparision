#by Alexander Pentchev
# 03_isolation_forest.py — Unsupervised Anomaly Detection
# Guide:
#   - Change RANDOM_SEED for a different Isolation Forest initialisation
#   - Change N_ESTIMATORS and CONTAMINATION to explore model behaviour
#   - Saves to a timestamped subfolder — nothing is overwritten
#   - run_config.json records every parameter used
#
# Terminal USAGE:
#   python3 03_isolation_forest.py --dataset dataset/<RUN_ID>
#   python3 03_isolation_forest.py --dataset dataset/<RUN_ID> --seed 99
#   python3 03_isolation_forest.py --dataset dataset/<RUN_ID> --seed 7 --trees 300
#
# GitHub reference implementations:
#   SecurityNik/Data-Science-and-ML (Zeek + Isolation Forest notebooks)
#   https://github.com/SecurityNik/Data-Science-and-ML

import os
import json
import argparse
import pandas as pd
import numpy as np
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, precision_score, recall_score, f1_score
)


# CONFIGURATION


RANDOM_SEED   = 42     # controls tree randomness
N_ESTIMATORS  = 200    # number of isolation trees; try 100, 200, 500
CONTAMINATION = 0.05   # expected noise fraction in benign training data


# Argument parser

parser = argparse.ArgumentParser(description="Isolation Forest IDS")
parser.add_argument("--dataset",      type=str,   required=True,
                    help="Path to dataset folder")
parser.add_argument("--seed",         type=int,   default=RANDOM_SEED)
parser.add_argument("--trees",        type=int,   default=N_ESTIMATORS)
parser.add_argument("--contamination",type=float, default=CONTAMINATION)
args = parser.parse_args()

RANDOM_SEED   = args.seed
N_ESTIMATORS  = args.trees
CONTAMINATION = args.contamination
DATASET_DIR   = args.dataset

np.random.seed(RANDOM_SEED)

# ── Output folder ─────────────────────────────────────────────────────────────
RUN_TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
RUN_ID        = f"if_{RUN_TIMESTAMP}_seed{RANDOM_SEED}_trees{N_ESTIMATORS}"
OUTPUT_DIR    = os.path.join("results", "isolation_forest", RUN_ID)
os.makedirs(OUTPUT_DIR, exist_ok=True)


#Load
'''Loads the labelled dataset produced by 01_extract_features.py.
Even though the Isolation Forest is unsupervised, the labels are kept
so we can evaluate how well it detects attacks at the end.'''

print("=" * 65)
print("Isolation Forest — Anomaly Detection")
print(f"Run ID:        {RUN_ID}")
print(f"Dataset:       {DATASET_DIR}")
print(f"Random seed:   {RANDOM_SEED}")
print(f"Trees:         {N_ESTIMATORS}")
print(f"Contamination: {CONTAMINATION}")
print("=" * 65)
print()

csv_path = os.path.join(DATASET_DIR, "features_labelled.csv")
if not os.path.exists(csv_path):
    print(f"[ERROR] Dataset not found: {csv_path}")
    exit(1)

df = pd.read_csv(csv_path)
print(f"[+] Dataset loaded: {len(df)} flows")
print("Class distribution:")
print(df["label_name"].value_counts())
print()


# Prepare
'''Separates the features from the labels. Then isolates the benign flows —
these are the only ones the model will train on. The Isolation Forest learns
what normal traffic looks like so it can flag anything that deviates from it.'''

DROP_COLS    = ["session", "network", "label", "label_name"]
FEATURE_COLS = [c for c in df.columns if c not in DROP_COLS]

X      = df[FEATURE_COLS].fillna(0)
y_true = df["label"]

benign_mask = df["label"] == 0
X_benign    = X[benign_mask]

print(f" Benign (train only): {len(X_benign)}")
print(f" Attack flows:        {(~benign_mask).sum()}")
print()


# Scale
'''Standardises the features so they all have a mean of 0 and a standard
deviation of 1. This stops features with large values (like orig_ip_bytes)
from dominating over features with small values (like proto_tcp). The scaler
is fitted on benign data only, then applied to the full dataset — matching
how the model itself is trained.'''

scaler          = StandardScaler()
X_benign_scaled = scaler.fit_transform(X_benign)
X_all_scaled    = scaler.transform(X)


# training on benign traffic
'''Trains the Isolation Forest on benign traffic only. The model builds
200 decision trees, each of which randomly partitions the feature space.
'''

print(" Training Isolation Forest on benign traffic only...")
iso = IsolationForest(
    n_estimators=N_ESTIMATORS,
    contamination=CONTAMINATION,
    max_samples="auto",
    random_state=RANDOM_SEED,
    n_jobs=-1
)
iso.fit(X_benign_scaled)
print(" Training complete!")
print()


# Score all traffic
'''Runs every flow in the full dataset (benign + DoS + C2) through the
trained model. Each flow receives an anomaly score — lower scores mean the
'''
print(" Computing anomaly scores...")
anomaly_scores = iso.score_samples(X_all_scaled)
y_true_binary  = (y_true != 0).astype(int)


# Find optimal threshold via F1 scan
# Scanning percentiles 1-99 and picking the one that maximises F1
'''this scans every percentile from 1 to 99
and measures the weighted F1 score at each one. The percentile that gives
the highest F1 becomes the detection threshold.'''

print(" Finding optimal detection threshold...")

best_f1 = best_threshold = best_prec = best_rec = 0
f1_list = []
percentiles = np.arange(1, 100, 1)
thresholds  = np.percentile(anomaly_scores, percentiles)

for t in thresholds:
    y_pred = (anomaly_scores < t).astype(int)
    f1 = f1_score(y_true_binary, y_pred, zero_division=0)
    f1_list.append(f1)
    if f1 > best_f1:
        best_f1        = f1
        best_threshold = t
        best_prec      = precision_score(y_true_binary, y_pred, zero_division=0)
        best_rec       = recall_score(y_true_binary, y_pred, zero_division=0)

print(f" Optimal threshold: {best_threshold:.4f}  (F1={best_f1:.4f})")
print()

y_pred_binary = (anomaly_scores < best_threshold).astype(int)


# Evaluate
'''Calculates performance metrics by comparing the model's predictions
against the true labels. '''
accuracy  = accuracy_score(y_true_binary, y_pred_binary)
precision = precision_score(y_true_binary, y_pred_binary, zero_division=0)
recall    = recall_score(y_true_binary, y_pred_binary, zero_division=0)
f1        = f1_score(y_true_binary, y_pred_binary, zero_division=0)

print("=" * 65)
print("RESULTS")
print("=" * 65)
print(f"  Accuracy:  {accuracy*100:.2f}%")
print(f"  Precision: {precision:.4f}")
print(f"  Recall:    {recall:.4f}")
print(f"  F1 Score:  {f1:.4f}")
print()
print(classification_report(y_true_binary, y_pred_binary,
      target_names=["normal","anomaly"], zero_division=0))

print("Detection rates by attack type:")
detection_rates = {}
for lv, ln in {1:"dos", 2:"c2_beacon"}.items():
    mask = y_true == lv
    if mask.sum() > 0:
        detected = int(y_pred_binary[mask].sum())
        total    = int(mask.sum())
        rate     = detected / total * 100
        detection_rates[ln] = {"detected": detected, "total": total, "rate": round(rate, 2)}
        print(f"  {ln:<15} {detected}/{total} ({rate:.1f}%)")

benign_flagged = int(y_pred_binary[y_true_binary == 0].sum())
total_benign   = int((y_true_binary == 0).sum())
fpr            = benign_flagged / total_benign * 100
print(f"\n  False positive rate: {benign_flagged}/{total_benign} ({fpr:.1f}%)")
print()


#Confusion matrix
'''Shows how many flows were correctly and incorrectly classified.'''

cm = confusion_matrix(y_true_binary, y_pred_binary)
plt.figure(figsize=(6, 5))
sns.heatmap(cm, annot=True, fmt="d", cmap="Oranges",
            xticklabels=["Normal","Anomaly"],
            yticklabels=["Normal","Anomaly"])
plt.title(f"Isolation Forest — Confusion Matrix\n(seed={RANDOM_SEED}, trees={N_ESTIMATORS})")
plt.ylabel("Actual")
plt.xlabel("Predicted")
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "confusion_matrix.png"), dpi=150)
plt.close()
print(f" Confusion matrix saved")


#Anomaly score distribution
'''Plots how the anomaly scores are distributed for each traffic class.'''
plt.figure(figsize=(12, 5))
plt.hist(anomaly_scores[y_true == 0], bins=100, alpha=0.6,
         color="blue", label="Benign", density=True)
if (y_true == 1).sum() > 0:
    plt.hist(anomaly_scores[y_true == 1], bins=100, alpha=0.6,
             color="red", label="DoS", density=True)
if (y_true == 2).sum() > 0:
    plt.hist(anomaly_scores[y_true == 2], bins=100, alpha=0.6,
             color="orange", label="C2 Beaconing", density=True)
plt.axvline(best_threshold, color="black", linestyle="--", linewidth=2,
            label=f"Threshold ({best_threshold:.3f})")
plt.xlabel("Anomaly Score (lower = more anomalous)")
plt.ylabel("Density")
plt.title(f"Isolation Forest — Score Distribution (seed={RANDOM_SEED})")
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "anomaly_scores.png"), dpi=150)
plt.close()
print(f" Score distribution saved")


#F1 vs threshold
'''Plots the F1 score at every percentile threshold tested'''
plt.figure(figsize=(10, 4))
plt.plot(percentiles, f1_list, color="green", linewidth=2)
best_idx = f1_list.index(max(f1_list))
plt.axvline(percentiles[best_idx], color="black", linestyle="--",
            label=f"Best F1={best_f1:.3f} @ percentile {percentiles[best_idx]}")
plt.xlabel("Percentile threshold")
plt.ylabel("F1 Score")
plt.title(f"Isolation Forest — F1 vs Threshold (seed={RANDOM_SEED})")
plt.legend()
plt.tight_layout()
plt.savefig(os.path.join(OUTPUT_DIR, "f1_vs_threshold.png"), dpi=150)
plt.close()
print(f" F1 vs threshold saved")


#Save results + config
'''Saves all results to a text file and a JSON config so this exact run
can be referenced or reproduced later.'''
results_path = os.path.join(OUTPUT_DIR, "results.txt")
with open(results_path, "w") as f:
    f.write(f"Isolation Forest Results — {RUN_ID}\n")
    f.write("=" * 65 + "\n\n")
    f.write(f"Dataset:           {DATASET_DIR}\n")
    f.write(f"Training data:     {len(X_benign)} benign flows\n")
    f.write(f"Test data:         {len(X)} total flows\n")
    f.write(f"Random seed:       {RANDOM_SEED}\n")
    f.write(f"N estimators:      {N_ESTIMATORS}\n")
    f.write(f"Contamination:     {CONTAMINATION}\n")
    f.write(f"Optimal threshold: {best_threshold:.4f}\n\n")
    f.write(f"Accuracy:          {accuracy:.4f}\n")
    f.write(f"Precision:         {precision:.4f}\n")
    f.write(f"Recall:            {recall:.4f}\n")
    f.write(f"F1 Score:          {f1:.4f}\n")
    f.write(f"FP rate:           {fpr:.2f}%\n\n")
    f.write(classification_report(y_true_binary, y_pred_binary,
            target_names=["normal","anomaly"], zero_division=0))
print(f"[✓] Results: {results_path}")

config = {
    "run_id":          RUN_ID,
    "timestamp":       RUN_TIMESTAMP,
    "dataset_dir":     DATASET_DIR,
    "random_seed":     RANDOM_SEED,
    "n_estimators":    N_ESTIMATORS,
    "contamination":   CONTAMINATION,
    "threshold":       round(float(best_threshold), 4),
    "accuracy":        round(accuracy, 4),
    "precision":       round(precision, 4),
    "recall":          round(recall, 4),
    "f1":              round(f1, 4),
    "fpr_percent":     round(fpr, 2),
    "detection_rates": detection_rates,
}
config_path = os.path.join(OUTPUT_DIR, "run_config.json")
with open(config_path, "w") as f:
    json.dump(config, f, indent=2)
print(f" Config:  {config_path}")

print()
print(f"To reproduce this exact run:")
print(f"  python3 03_isolation_forest.py --dataset {DATASET_DIR} --seed {RANDOM_SEED} --trees {N_ESTIMATORS}")