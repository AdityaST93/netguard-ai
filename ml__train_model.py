"""
NetGuard AI - Model training script.

Trains a RandomForestClassifier to distinguish normal traffic from
attack traffic (multi-class: normal / port_scan / dos / brute_force / ddos),
then saves the model + feature scaler to disk for use by ml/detector.py.

Usage:
    python ml/train_model.py --data data/sample_traffic.csv
"""
import argparse
import os
import sys

import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml.generate_synthetic_data import FEATURE_COLUMNS  # noqa: E402
from config import Config  # noqa: E402


def train(data_path: str, model_path: str, scaler_path: str):
    if not os.path.exists(data_path):
        raise FileNotFoundError(
            f"No dataset found at {data_path}. Run "
            f"'python ml/generate_synthetic_data.py --out {data_path}' first."
        )

    df = pd.read_csv(data_path)
    X = df[FEATURE_COLUMNS]
    y = df["label"]

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y
    )

    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)

    clf = RandomForestClassifier(
        n_estimators=200,
        max_depth=12,
        min_samples_leaf=3,
        random_state=42,
        n_jobs=-1,
        class_weight="balanced",
    )
    clf.fit(X_train_scaled, y_train)

    y_pred = clf.predict(X_test_scaled)
    print("=== Classification report ===")
    print(classification_report(y_test, y_pred))
    print("=== Confusion matrix ===")
    print(confusion_matrix(y_test, y_pred, labels=clf.classes_))
    print("Labels order:", list(clf.classes_))

    os.makedirs(os.path.dirname(model_path), exist_ok=True)
    joblib.dump(clf, model_path)
    joblib.dump(scaler, scaler_path)
    print(f"\nSaved model -> {model_path}")
    print(f"Saved scaler -> {scaler_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Train the NetGuard AI detection model")
    parser.add_argument("--data", default=Config.DATA_PATH)
    parser.add_argument("--model-out", default=Config.MODEL_PATH)
    parser.add_argument("--scaler-out", default=Config.SCALER_PATH)
    args = parser.parse_args()
    train(args.data, args.model_out, args.scaler_out)
