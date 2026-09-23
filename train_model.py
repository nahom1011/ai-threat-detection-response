import os
import glob
import joblib
import numpy as np
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix
)
from xgboost import XGBClassifier


BASE_DIR = r"D:\aaaaaaaaaaa my"
DATA_DIR = os.path.join(BASE_DIR, "MachineLearningCVE")
MODEL_DIR = os.path.join(BASE_DIR, "models")

os.makedirs(MODEL_DIR, exist_ok=True)

# These are the features that actually exist in CIC-IDS2017
DATASET_FEATURES = [
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Flow Bytes/s",
    "Flow Packets/s",
]

print("=" * 70)
print("AI THREAT DETECTION - XGBOOST TRAINING")
print("=" * 70)

files = glob.glob(os.path.join(DATA_DIR, "*.csv"))

datasets = []

for file in files:
    name = os.path.basename(file)

    # The DDoS file appears corrupted in your dataset, so skip it.
    print(f"\nChecking: {name}")

    try:
        df = pd.read_csv(
            file,
            encoding="latin1",
            low_memory=False
        )
    except Exception as e:
        print(f"[SKIP] Could not read file: {e}")
        continue

    # Remove whitespace around column names
    df.columns = df.columns.str.strip()

    if "Label" not in df.columns:
        print(f"[SKIP] {name} - no Label column")
        continue

    missing = [x for x in DATASET_FEATURES if x not in df.columns]

    if missing:
        print(f"[SKIP] {name}")
        print(f"Missing: {missing}")
        continue

    df = df[DATASET_FEATURES + ["Label"]].copy()

    # Convert features to numeric
    for col in DATASET_FEATURES:
        df[col] = pd.to_numeric(df[col], errors="coerce")

    # Replace infinity values
    df.replace([np.inf, -np.inf], np.nan, inplace=True)

    # Remove invalid rows
    df.dropna(inplace=True)

    # Normalize labels
    df["Label"] = df["Label"].astype(str).str.strip()

    print(f"[OK] {name}: {len(df):,} rows")

    datasets.append(df)


if not datasets:
    raise RuntimeError("No valid CIC-IDS2017 CSV files found.")


print("\n" + "=" * 70)
print("COMBINING DATASETS")
print("=" * 70)

data = pd.concat(datasets, ignore_index=True)

print(f"Total rows: {len(data):,}")

print("\nOriginal labels:")
print(data["Label"].value_counts())


# Convert labels to binary:
# BENIGN = 0
# Anything else = 1

data["target"] = (
    data["Label"]
    .str.upper()
    .ne("BENIGN")
    .astype(int)
)

print("\nBinary labels:")
print(data["target"].value_counts())


X = data[DATASET_FEATURES].copy()
y = data["target"]


# Replace extreme values
X = X.replace([np.inf, -np.inf], np.nan)

valid = X.notna().all(axis=1)

X = X.loc[valid]
y = y.loc[valid]


print("\nFinal dataset:")
print(f"Samples: {len(X):,}")
print(f"Benign: {(y == 0).sum():,}")
print(f"Malicious: {(y == 1).sum():,}")


# Train/test split
X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)


print("\nTraining samples:", len(X_train))
print("Testing samples:", len(X_test))


# Scale
scaler = StandardScaler()

X_train_scaled = scaler.fit_transform(X_train)
X_test_scaled = scaler.transform(X_test)


print("\nTraining XGBoost model...")


model = XGBClassifier(
    n_estimators=150,
    max_depth=6,
    learning_rate=0.1,
    subsample=0.8,
    colsample_bytree=0.8,
    objective="binary:logistic",
    eval_metric="logloss",
    random_state=42,
    n_jobs=-1
)

model.fit(
    X_train_scaled,
    y_train
)


# Evaluate
predictions = model.predict(X_test_scaled)

accuracy = accuracy_score(y_test, predictions)

print("\n" + "=" * 70)
print("MODEL EVALUATION")
print("=" * 70)

print(f"\nAccuracy: {accuracy:.4f}")

print("\nClassification Report:")
print(
    classification_report(
        y_test,
        predictions,
        target_names=["BENIGN", "MALICIOUS"],
        zero_division=0
    )
)

print("\nConfusion Matrix:")
print(confusion_matrix(y_test, predictions))


# Save model
model_path = os.path.join(MODEL_DIR, "xgboost.joblib")
scaler_path = os.path.join(MODEL_DIR, "scaler.joblib")

joblib.dump(model, model_path)
joblib.dump(scaler, scaler_path)


# Save feature names too
feature_path = os.path.join(MODEL_DIR, "feature_columns.joblib")

joblib.dump(DATASET_FEATURES, feature_path)


print("\n" + "=" * 70)
print("TRAINING COMPLETE")
print("=" * 70)

print(f"\nModel saved:")
print(model_path)

print("\nScaler saved:")
print(scaler_path)

print("\nFeatures saved:")
print(feature_path)

print("\nYour AI model is ready.")