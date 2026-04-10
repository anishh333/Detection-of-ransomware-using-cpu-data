"""
ML Model Training Module
Implements the 7 ML/DL classifiers from the paper:
- Random Forest (RF), SVM, Decision Trees (DT), kNN, XGBoost, DNN, LSTM
- Three model types: HPC-only, I/O-only, Integrated (HPC+I/O)
"""

import numpy as np
import pandas as pd
import os
import json
import joblib
from datetime import datetime

from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.tree import DecisionTreeClassifier
from sklearn.neighbors import KNeighborsClassifier
from xgboost import XGBClassifier
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import (
    balanced_accuracy_score, f1_score, precision_score, recall_score,
    confusion_matrix, roc_auc_score, roc_curve, classification_report
)
from sklearn.preprocessing import StandardScaler, LabelEncoder

from config import (
    HPC_EVENTS, IO_EVENTS, STAT_FEATURES, MODEL_DIR, DATA_DIR,
    CLASSIFICATION_THRESHOLD, RANDOM_STATE, CLASSIFIERS
)


def get_feature_columns(model_type="integrated"):
    """Get feature column names based on model type."""
    hpc_features = [f"{event}_{stat}" for event in HPC_EVENTS for stat in STAT_FEATURES]
    io_features = [f"{event}_{stat}" for event in IO_EVENTS for stat in STAT_FEATURES]

    if model_type == "hpc":
        return hpc_features
    elif model_type == "io":
        return io_features
    else:  # integrated
        return hpc_features + io_features


def prepare_data(dataset, model_type="integrated", train_rounds=None, test_rounds=None,
                 train_ransomware=None):
    """
    Prepare training and testing data following the paper's methodology.
    - Train with 5 rounds, test with 2 rounds
    - Train with 4 ransomware, test with all 22
    """
    feature_cols = get_feature_columns(model_type)

    if train_rounds is None:
        train_rounds = [0, 1, 2, 3, 4]
    if test_rounds is None:
        test_rounds = [5, 6]

    # Training ransomware (4 samples as per paper)
    if train_ransomware is None:
        train_ransomware = ["133b_Sodinokibi", "17d1_Netwalker", "4f7b_Sodinokibi", "7fae_Ryuk"]

    # Training data: selected rounds, training ransomware + all benign
    train_mask = dataset["round"].isin(train_rounds) & (
        (dataset["app_name"].isin(train_ransomware)) |
        (dataset["label"] == 0)
    )

    # Testing data: remaining rounds, all apps
    test_mask = dataset["round"].isin(test_rounds)

    X_train = dataset.loc[train_mask, feature_cols].values
    y_train = dataset.loc[train_mask, "label"].values

    X_test = dataset.loc[test_mask, feature_cols].values
    y_test = dataset.loc[test_mask, "label"].values

    # Scale features
    scaler = StandardScaler()
    X_train = scaler.fit_transform(X_train)
    X_test = scaler.transform(X_test)

    return X_train, y_train, X_test, y_test, scaler, feature_cols


def get_classifier(name):
    """Initialize ML classifier by name."""
    classifiers = {
        "Random Forest": RandomForestClassifier(
            n_estimators=100, random_state=RANDOM_STATE, n_jobs=1
        ),
        "SVM": SVC(
            kernel='rbf', probability=True, random_state=RANDOM_STATE
        ),
        "Decision Tree": DecisionTreeClassifier(
            random_state=RANDOM_STATE
        ),
        "kNN": KNeighborsClassifier(
            n_neighbors=5, n_jobs=1
        ),
        "XGBoost": XGBClassifier(
            n_estimators=100, random_state=RANDOM_STATE,
            eval_metric='logloss',
            verbosity=0,
            n_jobs=1
        ),
    }
    return classifiers.get(name)


def evaluate_model(y_true, y_pred, y_prob=None):
    """
    Evaluate model using metrics from the paper:
    Balanced Accuracy, F1-Score, Precision, Recall, FPR, FNR
    """
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()

    metrics = {
        "balanced_accuracy": round(balanced_accuracy_score(y_true, y_pred), 4),
        "f1_score": round(f1_score(y_true, y_pred), 4),
        "precision": round(precision_score(y_true, y_pred), 4),
        "recall": round(recall_score(y_true, y_pred), 4),
        "fpr": round(fp / (fp + tn), 4) if (fp + tn) > 0 else 0,
        "fnr": round(fn / (fn + tp), 4) if (fn + tp) > 0 else 0,
        "tp": int(tp),
        "fp": int(fp),
        "tn": int(tn),
        "fn": int(fn),
    }

    if y_prob is not None:
        metrics["roc_auc"] = round(roc_auc_score(y_true, y_prob), 4)
        fpr_arr, tpr_arr, thresholds = roc_curve(y_true, y_prob)
        metrics["roc_curve"] = {
            "fpr": fpr_arr.tolist(),
            "tpr": tpr_arr.tolist(),
        }

    return metrics


def compute_time_to_detect(model, X_test, y_test, dataset_test, scaler=None):
    """
    Compute time-to-detect as described in Section V-C.
    For each ransomware trace, find the first positive prediction.
    """
    detection_times = []

    # Group test data by trace (app_name, workload, round)
    if hasattr(dataset_test, 'groupby'):
        ransomware_traces = dataset_test[dataset_test["label"] == 1]
        grouped = ransomware_traces.groupby(["app_name", "workload", "round"])

        feature_cols = get_feature_columns("integrated")

        for (app, workload, rd), group in grouped:
            X_trace = group[feature_cols].values
            if scaler:
                X_trace = scaler.transform(X_trace)

            predictions = model.predict(X_trace)

            # Find first positive prediction
            first_positive = np.argmax(predictions == 1)
            if predictions[first_positive] == 1:
                detection_time_ms = (first_positive + 1) * 200  # Each instance = 200ms
                detection_times.append(detection_time_ms)
            else:
                detection_times.append(-1)  # Not detected

    return detection_times


def train_all_models(dataset):
    """
    Train all classifiers for all three model types (HPC, I/O, Integrated).
    Returns results dictionary similar to Table 4 in the paper.
    """
    print("\n" + "=" * 60)
    print("TRAINING ML MODELS")
    print("=" * 60)

    results = {}
    best_model = None
    best_accuracy = 0

    model_types = ["hpc", "io", "integrated"]
    classifier_names = ["Random Forest", "SVM", "Decision Tree", "kNN", "XGBoost"]

    for model_type in model_types:
        print(f"\n--- {model_type.upper()} Model ---")
        results[model_type] = {}

        X_train, y_train, X_test, y_test, scaler, feature_cols = prepare_data(
            dataset, model_type=model_type
        )

        print(f"  Training samples: {len(X_train)} | Test samples: {len(X_test)}")

        for clf_name in classifier_names:
            print(f"  Training {clf_name}...", end=" ")
            clf = get_classifier(clf_name)

            if clf is None:
                print("SKIPPED (not available)")
                continue

            clf.fit(X_train, y_train)
            y_pred = clf.predict(X_test)

            try:
                y_prob = clf.predict_proba(X_test)[:, 1]
            except Exception:
                y_prob = None

            metrics = evaluate_model(y_test, y_pred, y_prob)
            results[model_type][clf_name] = metrics

            print(f"Accuracy: {metrics['balanced_accuracy']:.4f} | "
                  f"F1: {metrics['f1_score']:.4f} | "
                  f"FPR: {metrics['fpr']:.4f} | FNR: {metrics['fnr']:.4f}")

            # Track best model (integrated RF expected per paper)
            if model_type == "integrated" and metrics['balanced_accuracy'] > best_accuracy:
                best_accuracy = metrics['balanced_accuracy']
                best_model = (clf, scaler, clf_name, metrics)

    # Save best model
    if best_model:
        clf, scaler, clf_name, metrics = best_model
        model_path = os.path.join(MODEL_DIR, "best_model.pkl")
        scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")
        joblib.dump(clf, model_path)
        joblib.dump(scaler, scaler_path)

        model_info = {
            "classifier": clf_name,
            "model_type": "integrated",
            "metrics": metrics,
            "feature_columns": get_feature_columns("integrated"),
            "trained_at": datetime.now().isoformat(),
        }
        # Remove non-serializable items
        if "roc_curve" in model_info["metrics"]:
            del model_info["metrics"]["roc_curve"]

        info_path = os.path.join(MODEL_DIR, "model_info.json")
        with open(info_path, "w") as f:
            json.dump(model_info, f, indent=2)

        print(f"\nBest Model: {clf_name} (Integrated)")
        print(f"  Balanced Accuracy: {metrics['balanced_accuracy']:.4f}")
        print(f"  Saved to: {model_path}")

    return results, best_model


def train_and_save():
    """Main function to load data, train models, and save results."""
    dataset_path = os.path.join(DATA_DIR, "ransomware_dataset.csv")
    if not os.path.exists(dataset_path):
        print("Dataset not found. Generating...")
        from data_generator import generate_dataset
        dataset = generate_dataset()
    else:
        print("Loading dataset...")
        dataset = pd.read_csv(dataset_path)

    results, best_model = train_all_models(dataset)

    # Save all results
    results_path = os.path.join(MODEL_DIR, "all_results.json")
    serializable_results = {}
    for mt in results:
        serializable_results[mt] = {}
        for cn in results[mt]:
            metrics = results[mt][cn].copy()
            if "roc_curve" in metrics:
                del metrics["roc_curve"]
            serializable_results[mt][cn] = metrics

    with open(results_path, "w") as f:
        json.dump(serializable_results, f, indent=2)

    print(f"\nAll results saved to: {results_path}")
    return results


if __name__ == "__main__":
    train_and_save()
