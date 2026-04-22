#by Alexander Pentchev

# 01_extract_features.py — Feature Extraction from Zeek conn.log

# Guide:
#   - Change RANDOM_SEED to get a different dataset shuffle each run
#   - Change DOS_BALANCE_MULTIPLIER to adjust class balance ratio
#   - Each run saves to a timestamped subfolder so nothing is overwritten
#   - A config.json is saved with every run so you know exactly what produced it
#
# USAGE:
#   python3 01_extract_features.py
#   python3 01_extract_features.py --seed 99 --balance 5
#
# OUTPUTS (in dataset/<RUN_ID>/):
#   features_labelled.csv    — for supervised Random Forest
#   features_unlabelled.csv  — for unsupervised Isolation Forest
#   run_config.json          — full config used for this run

import os
import json
import argparse
import pandas as pd
import numpy as np
from datetime import datetime


# CONFIGURATION — Edit these to change behaviour

# Sets the folder where the script looks for session folders
ZEEK_DATA_ROOT = os.path.dirname(os.path.abspath(__file__))

# Each session and its class label
# 0 = benign  |  1 = DoS  |  2 = C2 beaconing
SESSIONS = {
    "internet_baseline_11_20260415_221411":    0,
    "internet_baseline_12_20260415_225259":    0,
    "internet_baseline_13_20260416_000838":    0,
    "benign_01_hour_20260418_054126":    0,
    "dos_attack_internet_11_20260418_015634":     1,
    "dos_attack_internet_12_20260418_020927":  1,
    "dos_attack_internet_13_20260418_022249":  1,
    "internet_c2_03_20260416_050636":   2,
    "internet_c2_04_20260416_200525":   2,
    "internet_c2_05_20260416_210456":   2,
    "c2_01_hour_20260419_043056":    2,
}
_config_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "gui_sessions.json")
if os.path.exists(_config_path):
    with open(_config_path) as _f:
        SESSIONS = json.load(_f)


# Reproducibility controls
# Change RANDOM_SEED to produce a different dataset split/shuffle each time.
# Change DOS_BALANCE_MULTIPLIER to adjust how many DoS flows are kept
#   (as a multiple of the largest minority class).
RANDOM_SEED           = 42    # change this for a different run (e.g. 7, 99, 2025)
DOS_BALANCE_MULTIPLIER = 3    # controls dataset balancing


# Argument parser — override seed/balance from command line

parser = argparse.ArgumentParser(description="Feature extraction for IDS comparison")
parser.add_argument("--seed",    type=int, default=RANDOM_SEED,
                    help="Random seed (default: %(default)s)")
parser.add_argument("--balance", type=int, default=DOS_BALANCE_MULTIPLIER,
                    help="DoS balance multiplier (default: %(default)s)")
args = parser.parse_args()

RANDOM_SEED            = args.seed
DOS_BALANCE_MULTIPLIER = args.balance

np.random.seed(RANDOM_SEED)


# Output — timestamped subfolder so each run is preserved and can be identified
RUN_TIMESTAMP = datetime.now().strftime("%Y%m%d_%H%M%S")
RUN_ID        = f"run_{RUN_TIMESTAMP}_seed{RANDOM_SEED}"
OUTPUT_DIR    = os.path.join("dataset", RUN_ID)
os.makedirs(OUTPUT_DIR, exist_ok=True)


# Zeek conn.log field names
CONN_FIELDS = [
    "ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
    "proto", "service", "duration", "orig_bytes", "resp_bytes",
    "conn_state", "local_orig", "local_resp", "missed_bytes", "history",
    "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes",
    "tunnel_parents", "ip_proto"
]


# Load and extract from Zeek conn.log file, creates pandas DataFrame (like an excel table) with the data
#with the data
def load_conn_log(filepath):
    rows = []
    try:
        with open(filepath, "r") as f:
            for line in f:
                if line.startswith("#"):
                    continue
                parts = line.strip().split("\t")
                if len(parts) >= 20:
                    rows.append(parts[:22])
    except Exception as e:
        print(f"   *Error reading* {filepath}: {e}")
        return pd.DataFrame()
    if not rows:
        return pd.DataFrame()
    return pd.DataFrame(rows, columns=CONN_FIELDS[:len(rows[0])])

# Takes the Zeek connection log and extracts 34 features from each row
def extract_features(df):
    if df.empty:
        return pd.DataFrame()

    features = pd.DataFrame()

    for col in ["duration", "orig_bytes", "resp_bytes", "missed_bytes",
                "orig_pkts", "orig_ip_bytes", "resp_pkts", "resp_ip_bytes"]:
        if col in df.columns:
            df[col] = pd.to_numeric(df[col].replace("-", "0"),
                                    errors="coerce").fillna(0)

    df["id.orig_p"] = pd.to_numeric(df["id.orig_p"].replace("-", "0"),
                                    errors="coerce").fillna(0)
    df["id.resp_p"] = pd.to_numeric(df["id.resp_p"].replace("-", "0"),
                                    errors="coerce").fillna(0)
    df["ts"]        = pd.to_numeric(df["ts"].replace("-", "0"),
                                    errors="coerce").fillna(0)

    # Core
    features["duration"]        = df["duration"]
    features["orig_bytes"]      = df["orig_bytes"]
    features["resp_bytes"]      = df["resp_bytes"]
    features["missed_bytes"]    = df["missed_bytes"]
    features["orig_pkts"]       = df["orig_pkts"]
    features["resp_pkts"]       = df["resp_pkts"]
    features["orig_ip_bytes"]   = df["orig_ip_bytes"]
    features["resp_ip_bytes"]   = df["resp_ip_bytes"]
    features["dest_port"]       = df["id.resp_p"]
    features["src_port"]        = df["id.orig_p"]

    # Derived
    features["bytes_per_orig_pkt"] = np.where(
        df["orig_pkts"] > 0, df["orig_bytes"] / df["orig_pkts"], 0)
    features["bytes_per_resp_pkt"] = np.where(
        df["resp_pkts"] > 0, df["resp_bytes"] / df["resp_pkts"], 0)
    features["total_bytes"] = df["orig_bytes"] + df["resp_bytes"]
    features["total_pkts"]  = df["orig_pkts"]  + df["resp_pkts"]
    features["byte_ratio"]  = np.where(
        features["total_bytes"] > 0,
        df["orig_bytes"] / (features["total_bytes"] + 1), 0)

    # Protocol one-hot
    features["proto_tcp"]   = (df["proto"] == "tcp").astype(int)
    features["proto_udp"]   = (df["proto"] == "udp").astype(int)
    features["proto_icmp"]  = (df["proto"] == "icmp").astype(int)
    features["proto_other"] = (~df["proto"].isin(["tcp","udp","icmp"])).astype(int)

    # Service one-hot
    features["service_dns"]   = (df["service"] == "dns").astype(int)
    features["service_http"]  = (df["service"] == "http").astype(int)
    features["service_ftp"]   = (df["service"].isin(["ftp","ftp-data"])).astype(int)
    features["service_ssh"]   = (df["service"] == "ssh").astype(int)
    features["service_smtp"]  = (df["service"] == "smtp").astype(int)
    features["service_smb"]   = (df["service"].isin(["smb","gssapi,ntlm,smb,dce_rpc"])).astype(int)
    features["service_mqtt"]  = (df["service"] == "mqtt").astype(int)
    features["service_dhcp"]  = (df["service"] == "dhcp").astype(int)
    features["service_other"] = (~df["service"].isin([
        "dns","http","ftp","ftp-data","ssh","smtp","smb","mqtt","dhcp","-"
    ])).astype(int)

    # Connection state one-hot
    features["state_SF"]  = (df["conn_state"] == "SF").astype(int)
    features["state_S0"]  = (df["conn_state"] == "S0").astype(int)
    features["state_REJ"] = (df["conn_state"] == "REJ").astype(int)
    features["state_OTH"] = (df["conn_state"] == "OTH").astype(int)

    # Port flags
    features["is_wellknown_port"]   = (df["id.resp_p"].astype(float) < 1024).astype(int)
    features["is_nonstandard_port"] = (
        ~df["id.resp_p"].astype(float).isin([21,22,25,53,80,110,143,443,445,1883,3306])
    ).astype(int)

    return features.reset_index(drop=True)


# ============================================================================
# MAIN
# ============================================================================
print("=" * 65)
print("Feature Extraction from Zeek conn.log files")
print(f"Run ID:      {RUN_ID}")
print(f"Random seed: {RANDOM_SEED}")
print(f"DoS balance: {DOS_BALANCE_MULTIPLIER}x minority class")
print("=" * 65)
print()

all_features = []

for session_name, label in SESSIONS.items():
    label_name = {0:"benign", 1:"dos", 2:"c2_beacon"}.get(label, "unknown")
    print(f" {session_name} ({label_name})")
    for network in ["office", "iot"]:
        log_path = os.path.join(ZEEK_DATA_ROOT, session_name, network, "conn.log")
        if not os.path.exists(log_path):
            print(f"   *Not found*: {log_path}")
            continue
        df = load_conn_log(log_path)
        if df.empty:
            continue
        feats = extract_features(df)
        if feats.empty:
            continue
        feats["session"]    = session_name
        feats["network"]    = network
        feats["label"]      = label
        feats["label_name"] = label_name
        all_features.append(feats)
        print(f"   {network}: {len(feats)} flows")

print()

if not all_features:
    print("[ERROR] No features extracted. Check SESSIONS paths.")
    exit(1)

combined = pd.concat(all_features, ignore_index=True)
print(f" Total flows before balancing: {len(combined)}")
print("Label distribution (raw):")
print(combined["label_name"].value_counts())
print()

# Dataset Balancing
'''This downsamples the DoS class. It keeps all benign and C2 flows, 
but randomly samples only target_size DoS flows. Then shuffles the entire dataset. '''

print(f" Balancing dataset (seed={RANDOM_SEED}, multiplier={DOS_BALANCE_MULTIPLIER})...")
benign_count = len(combined[combined["label"] == 0])
c2_count     = len(combined[combined["label"] == 2])
target_size  = max(benign_count, c2_count) * DOS_BALANCE_MULTIPLIER

dos_sample = combined[combined["label"] == 1].sample(
    n=min(target_size, len(combined[combined["label"] == 1])),
    random_state=RANDOM_SEED
)

combined = pd.concat([
    combined[combined["label"] == 0],
    dos_sample,
    combined[combined["label"] == 2]
], ignore_index=True).sample(frac=1, random_state=RANDOM_SEED).reset_index(drop=True)

print(f" Balanced dataset size: {len(combined)}")
print("Label distribution (balanced):")
print(combined["label_name"].value_counts())
print()

# Save
labelled_path = os.path.join(OUTPUT_DIR, "features_labelled.csv")
combined.to_csv(labelled_path, index=False)
print(f" Labelled dataset:   {labelled_path}")

feature_cols = [c for c in combined.columns
                if c not in ["session","network","label","label_name"]]
unlabelled_path = os.path.join(OUTPUT_DIR, "features_unlabelled.csv")
combined[feature_cols].to_csv(unlabelled_path, index=False)
print(f" Unlabelled dataset: {unlabelled_path}")
#features_unlabelled, just the features and no labels (used for IF).
#features_labelled has all features labbelled for Random Forest.
# Save run config
config = {
    "run_id":                RUN_ID,
    "timestamp":             RUN_TIMESTAMP,
    "random_seed":           RANDOM_SEED,
    "dos_balance_multiplier": DOS_BALANCE_MULTIPLIER,
    "zeek_data_root":        ZEEK_DATA_ROOT,
    "sessions":              SESSIONS,
    "total_flows":           len(combined),
    "label_counts":          combined["label_name"].value_counts().to_dict(),
    "feature_columns":       feature_cols,
    "n_features":            len(feature_cols),
}
config_path = os.path.join(OUTPUT_DIR, "run_config.json")
with open(config_path, "w") as f:
    json.dump(config, f, indent=2)
print(f" Run config saved:   {config_path}")
print()
print(f"Next step: pass this run folder to the ML scripts:")
print(f"  python3 02_random_forest.py   --dataset {OUTPUT_DIR}")
print(f"  python3 03_isolation_forest.py --dataset {OUTPUT_DIR}")