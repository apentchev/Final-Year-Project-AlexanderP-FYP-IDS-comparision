#by Alexander Pentchev
# 02_random_forest.py — Supervised Intrusion Detection
# Guide:
#   - Change RANDOM_SEED to get a different train/test split each run
#   - Change N_ESTIMATORS, MAX_DEPTH for different model configurations
#   - Saves results to a timestamped subfolder — nothing is overwritten
#   - run_config.json records every parameter used
#
# USAGE in terminal:
#   python3 02_random_forest.py --dataset dataset/<RUN_ID>
#   python3 02_random_forest.py --dataset dataset/<RUN_ID> --seed 99
#   python3 02_random_forest.py --dataset dataset/<RUN_ID> --seed 7 --trees 200
# or follow the instruction in the GUI
# GitHub reference implementations:
#   Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning
#   https://github.com/Western-OC2-Lab/Intrusion-Detection-System-Using-Machine-Learning


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

from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import (
    classification_report, confusion_matrix,
    accuracy_score, precision_score, recall_score, f1_score
)
import joblib


# CONFIGURATION — Change these values to explore different models

RANDOM_SEED  = 42     # controls train/test split + forest randomness
N_ESTIMATORS = 100    # number of trees in the forest
MAX_DEPTH    = None   # None = fully grown trees; try 10, 20, 50
TEST_SIZE    = 0.20   # fraction of data held out for testing


# Argument parser — override all config from the command line
parser = argparse.ArgumentParser(description="Random Forest IDS")
parser.add_argument("--dataset", type=str, required=True,
                    help="Path to dataset folder (e.g. dataset/run_20260404_seed42)")
parser.add_argument("--seed",    type=int, default=RANDOM_SEED,
                    help="Random seed (default: %(default)s)")
parser.add_argument("--trees",   type=int, default=N_ESTIMATORS,
                    help="Number of estimators (default: %(default)s)")
parser.add_argument("--depth",   type=int, default=None,
                    help="Max tree depth (default: None = unlimited)")
parser.add_argument("--test",    type=float, default=TEST_SIZE,
                    help="Test set fraction 0-1 (default: %(default)s)")
args = parser.parse_args()

RANDOM_SEED  = args.seed
N_ESTIMATORS = args.trees
MAX_DEPTH    = args.depth
TEST_SIZE    = args.test
DATASET_DIR  = args.dataset

np.random.seed(RANDOM_SEED)

#  Output folder
RUN_TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
RUN_ID        = f"rf_{RUN_TIMESTAMP}_seed{RANDOM_SEED}_trees{N_ESTIMATORS}"
OUTPUT_DIR    = os.path.join("results", "random_forest", RUN_ID)
os.makedirs(OUTPUT_DIR, exist_ok=True)


# Loads dataset
print("=" * 65)
print("Random Forest — Intrusion Detection")
print(f"Run ID:        {RUN_ID}")
print(f"Dataset:       {DATASET_DIR}")
print(f"Random seed:   {RANDOM_SEED}")
print(f"Trees:         {N_ESTIMATORS}")
print(f"Max depth:     {MAX_DEPTH}")
print(f"Test fraction: {TEST_SIZE}")
print("=" * 65)
print()

csv_path = os.path.join(DATASET_DIR, "features_labelled.csv")
if not os.path.exists(csv_path):
    print(f"[ERROR] Dataset not found: {csv_path}")
    exit(1)

df = pd.read_csv(csv_path)
print(f" Dataset loaded: {len(df)} flows")
print("Class distribution:")
print(df["label_name"].value_counts())
print()


# Feature preparation and labels
DROP_COLS    = ["session", "network", "label", "label_name"]
FEATURE_COLS = [c for c in df.columns if c not in DROP_COLS]

X = df[FEATURE_COLS].fillna(0)
y = df["label"]

print(f" Features: {len(FEATURE_COLS)}")


# Train/test split
'''Splits the 80/20, stratify=y maintaining the 
 same proportion of each class in both train and test sets'''
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=TEST_SIZE,
    random_state=RANDOM_SEED,
    stratify=y
)

print(f" Train: {len(X_train)} | Test: {len(X_test)}")
print()

# Training model
'''Creates the Random Forest model and trains it on the training data.'''
print("Training Random Forest...")
rf = RandomForestClassifier(
    n_estimators=N_ESTIMATORS,
    max_depth=MAX_DEPTH,
    min_samples_split=2,
    random_state=RANDOM_SEED,
    n_jobs=-1,
    class_weight="balanced"
)
rf.fit(X_train, y_train)
print("Training complete!")
print()


# Evaluation
'''Makes predictions on the test set and calculates metrics. '''
y_pred    = rf.predict(X_test)
accuracy  = accuracy_score(y_test, y_pred)
precision = precision_score(y_test, y_pred, average="weighted", zero_division=0)
recall    = recall_score(y_test, y_pred,    average="weighted", zero_division=0)
f1        = f1_score(y_test, y_pred,        average="weighted", zero_division=0)

label_map    = {0:"benign", 1:"dos", 2:"c2_beacon"}
target_names = [label_map[i] for i in sorted(y.unique())]

print("=" * 65)
print("RESULTS")
print("=" * 65)
print(f"  Accuracy:  {accuracy*100:.2f}%")
print(f"  Precision: {precision:.4f}")
print(f"  Recall:    {recall:.4f}")
print(f"  F1 Score:  {f1:.4f}")
print()
print(classification_report(y_test, y_pred, target_names=target_names, zero_division=0))


# Cross validation (5-fold)
'''Performs 5-fold cross-validation — splits the data into 5 parts, 
trains on 4 and tests on 1, repeats 5 times, and averages the results. '''

print(" 5-fold cross validation...")
cv_scores = cross_val_score(rf, X, y, cv=5, scoring="f1_weighted", n_jobs=-1)
print(f"  CV F1: {cv_scores.mean():.4f} (+/- {cv_scores.std():.4f})")
print(f"  Scores: {cv_scores}")
print()


# Confusion matrix
'''Creates a confusion matrix showing how many flows were 
correctly/incorrectly classified for each class. Saves it as a PNG image.'''
cm = confusion_matrix(y_test, y_pred)
plt.figure(figsize=(8, 6))
sns.heatmap(cm, annot=True, fmt="d", cmap="Blues",
            xticklabels=target_names, yticklabels=target_names)
plt.title(f"Random Forest — Confusion Matrix\n(seed={RANDOM_SEED}, trees={N_ESTIMATORS})")
plt.ylabel("Actual")
plt.xlabel("Predicted")
plt.tight_layout()
cm_path = os.path.join(OUTPUT_DIR, "confusion_matrix.png")
plt.savefig(cm_path, dpi=150)
plt.close()
print(f" Confusion matrix: {cm_path}")


# Feature importance

importances = pd.Series(rf.feature_importances_, index=FEATURE_COLS).sort_values(ascending=False)
plt.figure(figsize=(10, 8))
importances.head(20).plot(kind="barh")
plt.title(f"Random Forest — Top 20 Features\n(seed={RANDOM_SEED})")
plt.xlabel("Importance Score")
plt.gca().invert_yaxis()
plt.tight_layout()
fi_path = os.path.join(OUTPUT_DIR, "feature_importance.png")
plt.savefig(fi_path, dpi=150)
plt.close()
print(f" Feature importance: {fi_path}")

print("\nTop 10 features:")
for feat, score in importances.head(10).items():
    print(f"  {feat:<30} {score:.4f}")
print()


#Save results + config
'''Random Forest can tell you which features it used most for making decisions.'''

results_path = os.path.join(OUTPUT_DIR, "results.txt")
with open(results_path, "w") as f:
    f.write(f"Random Forest Results — {RUN_ID}\n")
    f.write("=" * 65 + "\n\n")
    f.write(f"Dataset:        {DATASET_DIR}\n")
    f.write(f"Dataset size:   {len(df)}\n")
    f.write(f"Train/test:     {len(X_train)}/{len(X_test)}\n")
    f.write(f"Random seed:    {RANDOM_SEED}\n")
    f.write(f"N estimators:   {N_ESTIMATORS}\n")
    f.write(f"Max depth:      {MAX_DEPTH}\n\n")
    f.write(f"Accuracy:       {accuracy:.4f}\n")
    f.write(f"Precision:      {precision:.4f}\n")
    f.write(f"Recall:         {recall:.4f}\n")
    f.write(f"F1 Score:       {f1:.4f}\n")
    f.write(f"CV F1 mean:     {cv_scores.mean():.4f}\n")
    f.write(f"CV F1 std:      {cv_scores.std():.4f}\n\n")
    f.write("Classification Report:\n")
    f.write(classification_report(y_test, y_pred, target_names=target_names, zero_division=0))
    f.write("\nTop 10 Feature Importances:\n")
    for feat, score in importances.head(10).items():
        f.write(f"  {feat:<30} {score:.4f}\n")
print(f" Results: {results_path}")

config = {
    "run_id":        RUN_ID,
    "timestamp":     RUN_TIMESTAMP,
    "dataset_dir":   DATASET_DIR,
    "random_seed":   RANDOM_SEED,
    "n_estimators":  N_ESTIMATORS,
    "max_depth":     MAX_DEPTH,
    "test_size":     TEST_SIZE,
    "accuracy":      round(accuracy, 4),
    "precision":     round(precision, 4),
    "recall":        round(recall, 4),
    "f1":            round(f1, 4),
    "cv_f1_mean":    round(float(cv_scores.mean()), 4),
    "cv_f1_std":     round(float(cv_scores.std()), 4),
}
config_path = os.path.join(OUTPUT_DIR, "run_config.json")
with open(config_path, "w") as f:
    json.dump(config, f, indent=2)
print(f" Config:  {config_path}")

model_path = os.path.join(OUTPUT_DIR, "random_forest_model.pkl")
joblib.dump(rf, model_path)
print(f" Model:   {model_path}")

print()
print(f"To reproduce this exact run:")
print(f"  python3 02_random_forest.py --dataset {DATASET_DIR} --seed {RANDOM_SEED} --trees {N_ESTIMATORS}")