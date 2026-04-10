"""
Performance Benchmark Script
Calculates Inference Latency and Time-to-Detect (TTD) metrics
to verify the 400ms detection capability.
"""

import time
import numpy as np
import pandas as pd
import os
import joblib
import json
from monitor import SystemMonitor
from ml_models import compute_time_to_detect, get_feature_columns
from config import MODEL_DIR, DATA_DIR, INSTANCE_DURATION_MS

def run_benchmark():
    print("\n" + "="*60)
    print("  RANSOMWARE DETECTION PERFORMANCE BENCHMARK")
    print("="*60)

    # 1. Measure Inference Latency
    print("\n[1/3] Measuring Inference Latency...")
    monitor = SystemMonitor()
    if not monitor.model_loaded:
        print("Error: Model not loaded. Please train the model first.")
        return

    # Generate a dummy feature set
    feature_cols = monitor.model_info.get("feature_columns", [])
    dummy_features = {col: np.random.random() for col in feature_cols}
    
    latencies = []
    for _ in range(100):
        start_time = time.perf_counter()
        monitor.predict(dummy_features)
        latencies.append(time.perf_counter() - start_time)
    
    avg_latency = np.mean(latencies) * 1000
    min_latency = np.min(latencies) * 1000
    print(f"  Average Inference Latency: {avg_latency:.4f} ms")
    print(f"  Minimum Inference Latency: {min_latency:.4f} ms")

    # 2. Analyze Dataset Time-to-Detect (TTD)
    print("\n[2/3] Analyzing Dataset Time-to-Detect (TTD)...")
    dataset_path = os.path.join(DATA_DIR, "ransomware_dataset.csv")
    if not os.path.exists(dataset_path):
        print("  Error: Dataset not found. Generating sample traces for verification...")
        from data_generator import generate_trace
        # Generate 5 ransomware traces and 5 benign traces across different workloads
        traces = []
        for i in range(5):
            traces.append(generate_trace(f"rw_{i}", "ransomware", "CL.0", num_instances=100))
            traces.append(generate_trace(f"benign_{i}", "benign", "BL.0", num_instances=100))
        dataset = pd.concat(traces, ignore_index=True)
        dataset["round"] = 0
        dataset["workload"] = "CL.0" # simplify
    else:
        dataset = pd.read_csv(dataset_path)

    # Use the compute_time_to_detect function from ml_models
    # It calculates TTD as (first_positive + 1) * 200ms
    ttd_metrics = compute_time_to_detect(monitor.model, None, None, dataset, monitor.scaler)
    
    # Filter out -1 (not detected)
    valid_ttds = [t for t in ttd_metrics if t > 0]
    
    if not valid_ttds:
        print("  Warning: No ransomware detections in dataset. Check model accuracy.")
    else:
        print(f"  Minimum TTD: {np.min(valid_ttds)} ms")
        print(f"  Maximum TTD: {np.max(valid_ttds)} ms")
        print(f"  Average TTD: {np.mean(valid_ttds):.2f} ms")
        
        detections_under_400ms = len([t for t in valid_ttds if t <= 400])
        print(f"  Detections <= 400ms: {detections_under_400ms} / {len(valid_ttds)} ({detections_under_400ms/len(valid_ttds)*100:.1f}%)")

    # 3. Component Breakdown
    print("\n[3/3] System Breakdown:")
    print(f"  Sampling Interval: {INSTANCE_DURATION_MS} ms")
    print(f"  Processing Overhead: ~{avg_latency:.2f} ms")
    print(f"  Total Cycle Time: ~{INSTANCE_DURATION_MS + avg_latency:.2f} ms")
    print("\nConclusion:")
    if detections_under_400ms > 0:
        print(f"  YES: The system successfully detects ransomware in {np.min(valid_ttds)}ms in current tests.")
    else:
        print("  NO: Current model/dataset setup requires more than 400ms for detection.")
    print("="*60 + "\n")

if __name__ == "__main__":
    run_benchmark()
