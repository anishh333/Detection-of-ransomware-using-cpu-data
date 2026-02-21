"""
Data Generator Module
Simulates HPC and Disk I/O data collection as described in the paper.
Since we cannot run actual ransomware, we simulate realistic data patterns
that mimic the behavior described in the research paper.
"""

import numpy as np
import pandas as pd
import os
from config import (
    HPC_EVENTS, IO_EVENTS, STAT_FEATURES, DATA_DIR,
    HPC_SAMPLES_PER_INSTANCE, IO_SAMPLES_PER_INSTANCE,
    TOTAL_INSTANCES_PER_TRACE, WORKLOAD_TYPES, BENIGN_APPS,
    RANSOMWARE_FAMILIES, RANDOM_STATE
)

np.random.seed(RANDOM_STATE)


def generate_hpc_raw_samples(app_type, workload, num_samples=40):
    """
    Generate raw HPC event samples for a single instance (200ms window).
    Patterns are based on the paper's observations:
    - Ransomware shows elevated LLC-stores, L1-icache-load-misses,
      branch-load-misses, and instruction counts
    - Different workloads shift the baseline significantly
    """
    base_profiles = {
        "BL.0": {"LLC-stores": 5000, "L1-icache-load-misses": 3000,
                 "branch-load-misses": 2000, "node-load-misses": 1000, "instructions": 50000},
        "CL.0": {"LLC-stores": 15000, "L1-icache-load-misses": 8000,
                 "branch-load-misses": 6000, "node-load-misses": 3000, "instructions": 150000},
        "CL.1": {"LLC-stores": 12000, "L1-icache-load-misses": 7000,
                 "branch-load-misses": 5000, "node-load-misses": 2500, "instructions": 130000},
        "CL.2": {"LLC-stores": 18000, "L1-icache-load-misses": 9000,
                 "branch-load-misses": 7000, "node-load-misses": 3500, "instructions": 180000},
        "NL.0": {"LLC-stores": 10000, "L1-icache-load-misses": 12000,
                 "branch-load-misses": 4000, "node-load-misses": 5000, "instructions": 120000},
        "NL.1": {"LLC-stores": 11000, "L1-icache-load-misses": 11000,
                 "branch-load-misses": 4500, "node-load-misses": 4500, "instructions": 125000},
    }

    base = base_profiles.get(workload, base_profiles["BL.0"])
    samples = {}

    for event in HPC_EVENTS:
        base_val = base[event]
        noise_level = base_val * 0.15

        if app_type == "ransomware":
            # Ransomware shows significantly elevated activity
            multiplier = np.random.uniform(2.5, 5.0)
            burst_noise = base_val * np.random.uniform(0.2, 0.6)
            values = np.random.normal(base_val * multiplier, burst_noise, num_samples)
            # Add occasional spikes (encryption bursts)
            spike_indices = np.random.choice(num_samples, size=max(1, num_samples // 5), replace=False)
            values[spike_indices] *= np.random.uniform(1.5, 3.0, len(spike_indices))
        elif app_type in ["7zip", "aesCrypt"]:
            # Benign apps that mimic ransomware-like behavior
            multiplier = np.random.uniform(1.5, 2.5)
            values = np.random.normal(base_val * multiplier, noise_level * 1.5, num_samples)
        elif app_type == "sDelete":
            # File deletion activity
            multiplier = np.random.uniform(1.2, 1.8)
            values = np.random.normal(base_val * multiplier, noise_level, num_samples)
        else:  # dryRun
            values = np.random.normal(base_val, noise_level, num_samples)

        samples[event] = np.maximum(values, 0).astype(int)

    return samples


def generate_io_raw_samples(app_type, workload, num_samples=10):
    """
    Generate raw disk I/O event samples for a single instance (200ms).
    Ransomware shows heavy read + write activity due to file encryption.
    """
    base_io = {
        "BL.0": {"rd_req": 50, "rd_bytes": 51200, "wr_req": 20, "wr_bytes": 20480,
                 "flush_req": 5, "flush_total_times": 100, "rd_total_times": 500, "wr_total_times": 200},
        "CL.0": {"rd_req": 200, "rd_bytes": 204800, "wr_req": 80, "wr_bytes": 81920,
                 "flush_req": 15, "flush_total_times": 300, "rd_total_times": 1500, "wr_total_times": 800},
        "CL.1": {"rd_req": 160, "rd_bytes": 163840, "wr_req": 65, "wr_bytes": 66560,
                 "flush_req": 12, "flush_total_times": 250, "rd_total_times": 1200, "wr_total_times": 650},
        "CL.2": {"rd_req": 250, "rd_bytes": 256000, "wr_req": 100, "wr_bytes": 102400,
                 "flush_req": 18, "flush_total_times": 350, "rd_total_times": 1800, "wr_total_times": 1000},
        "NL.0": {"rd_req": 150, "rd_bytes": 153600, "wr_req": 120, "wr_bytes": 122880,
                 "flush_req": 25, "flush_total_times": 500, "rd_total_times": 1000, "wr_total_times": 1200},
        "NL.1": {"rd_req": 140, "rd_bytes": 143360, "wr_req": 110, "wr_bytes": 112640,
                 "flush_req": 22, "flush_total_times": 450, "rd_total_times": 950, "wr_total_times": 1100},
    }

    base = base_io.get(workload, base_io["BL.0"])
    samples = {}

    for event in IO_EVENTS:
        base_val = base[event]
        noise_level = base_val * 0.12

        if app_type == "ransomware":
            multiplier = np.random.uniform(3.0, 6.0)
            values = np.random.normal(base_val * multiplier, base_val * 0.4, num_samples)
            spike_indices = np.random.choice(num_samples, size=max(1, num_samples // 4), replace=False)
            values[spike_indices] *= np.random.uniform(1.3, 2.5, len(spike_indices))
        elif app_type in ["7zip", "aesCrypt"]:
            multiplier = np.random.uniform(1.8, 3.0)
            values = np.random.normal(base_val * multiplier, noise_level * 2, num_samples)
        elif app_type == "sDelete":
            multiplier = np.random.uniform(1.5, 2.5)
            values = np.random.normal(base_val * multiplier, noise_level * 1.5, num_samples)
        else:
            values = np.random.normal(base_val, noise_level, num_samples)

        samples[event] = np.maximum(values, 0).astype(int)

    return samples


def compute_statistical_features(raw_samples):
    """
    Compute 4 statistical features (mean, median, std, IQR) per event.
    As described in Section III-B of the paper.
    """
    features = {}
    for event, values in raw_samples.items():
        features[f"{event}_mean"] = np.mean(values)
        features[f"{event}_median"] = np.median(values)
        features[f"{event}_std"] = np.std(values)
        features[f"{event}_iqr"] = np.percentile(values, 75) - np.percentile(values, 25)
    return features


def generate_trace(app_name, app_type, workload, num_instances=300):
    """
    Generate a complete data trace (60 seconds of data).
    Each trace has 300 instances of HPC and I/O data.
    """
    instances = []
    for i in range(num_instances):
        hpc_raw = generate_hpc_raw_samples(app_type, workload)
        io_raw = generate_io_raw_samples(app_type, workload)

        hpc_features = compute_statistical_features(hpc_raw)
        io_features = compute_statistical_features(io_raw)

        instance = {**hpc_features, **io_features}
        instance["instance_id"] = i
        instance["timestamp_ms"] = i * 200  # Each instance = 200ms
        instance["app_name"] = app_name
        instance["workload"] = workload
        instance["label"] = 1 if app_type == "ransomware" else 0
        instances.append(instance)

    return pd.DataFrame(instances)


def generate_dataset(num_rounds=7):
    """
    Generate complete dataset matching the paper's methodology.
    26 apps × 6 workloads × 7 rounds = 1092 traces
    """
    print("=" * 60)
    print("GENERATING SIMULATED DATASET")
    print("Based on paper methodology: 26 apps × 6 workloads × 7 rounds")
    print("=" * 60)

    all_traces = []

    # Ransomware samples
    ransomware_samples = []
    for family, samples in RANSOMWARE_FAMILIES.items():
        for sample_id in samples:
            ransomware_samples.append((sample_id, family))

    # Pad to 22 ransomware samples as per paper
    while len(ransomware_samples) < 22:
        family = list(RANSOMWARE_FAMILIES.keys())[len(ransomware_samples) % len(RANSOMWARE_FAMILIES)]
        sample_id = f"rw{len(ransomware_samples):02d}"
        ransomware_samples.append((sample_id, family))

    total_traces = (len(ransomware_samples) + len(BENIGN_APPS)) * len(WORKLOAD_TYPES) * num_rounds
    trace_count = 0

    for round_num in range(num_rounds):
        for workload in WORKLOAD_TYPES:
            # Ransomware traces
            for sample_id, family in ransomware_samples:
                trace = generate_trace(
                    app_name=f"{sample_id}_{family}",
                    app_type="ransomware",
                    workload=workload,
                    num_instances=TOTAL_INSTANCES_PER_TRACE
                )
                trace["round"] = round_num
                trace["family"] = family
                all_traces.append(trace)
                trace_count += 1

            # Benign traces
            for app in BENIGN_APPS:
                trace = generate_trace(
                    app_name=app,
                    app_type=app,
                    workload=workload,
                    num_instances=TOTAL_INSTANCES_PER_TRACE
                )
                trace["round"] = round_num
                trace["family"] = "benign"
                all_traces.append(trace)
                trace_count += 1

        print(f"  Round {round_num + 1}/{num_rounds} completed ({trace_count}/{total_traces} traces)")

    dataset = pd.concat(all_traces, ignore_index=True)
    dataset_path = os.path.join(DATA_DIR, "ransomware_dataset.csv")
    dataset.to_csv(dataset_path, index=False)

    print(f"\nDataset generated: {dataset.shape[0]} instances")
    print(f"Saved to: {dataset_path}")
    print(f"Ransomware instances: {(dataset['label'] == 1).sum()}")
    print(f"Benign instances: {(dataset['label'] == 0).sum()}")

    return dataset


if __name__ == "__main__":
    dataset = generate_dataset()
    print("\nDataset columns:")
    print(dataset.columns.tolist())
    print("\nDataset sample:")
    print(dataset.head())
