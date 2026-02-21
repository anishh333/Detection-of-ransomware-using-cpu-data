"""
Real-time System Monitor
Collects actual CPU and Disk I/O metrics from the host system
using psutil, and uses the trained ML model for live detection.
"""

import psutil
import time
import numpy as np
import joblib
import os
import json
from collections import deque
from config import HPC_EVENTS, IO_EVENTS, STAT_FEATURES, MODEL_DIR


class SystemMonitor:
    """
    Monitors system CPU and Disk I/O activity in real-time.
    Maps psutil metrics to the paper's HPC and I/O event features.
    """

    def __init__(self, sampling_interval_ms=200, window_size=40):
        self.sampling_interval = sampling_interval_ms / 1000.0
        self.window_size = window_size
        self.io_window_size = 10

        # Buffers for raw samples
        self.hpc_buffer = {event: deque(maxlen=window_size) for event in HPC_EVENTS}
        self.io_buffer = {event: deque(maxlen=self.io_window_size) for event in IO_EVENTS}

        # Load trained model
        model_path = os.path.join(MODEL_DIR, "best_model.pkl")
        scaler_path = os.path.join(MODEL_DIR, "scaler.pkl")
        info_path = os.path.join(MODEL_DIR, "model_info.json")

        if os.path.exists(model_path):
            self.model = joblib.load(model_path)
            self.scaler = joblib.load(scaler_path)
            with open(info_path, "r") as f:
                self.model_info = json.load(f)
            self.model_loaded = True
        else:
            self.model = None
            self.scaler = None
            self.model_info = None
            self.model_loaded = False

        self.is_monitoring = False
        self.detection_history = []

    def collect_sample(self):
        """Collect one sample of system metrics."""
        # CPU metrics (mapped to HPC events)
        cpu_percent = psutil.cpu_percent(interval=None, percpu=True)
        cpu_times = psutil.cpu_times()
        cpu_stats = psutil.cpu_stats()
        cpu_freq = psutil.cpu_freq()

        # Map to HPC events (approximate mapping since we can't access actual HPCs)
        avg_cpu = np.mean(cpu_percent) if cpu_percent else 0
        hpc_sample = {
            "LLC-stores": int(cpu_stats.ctx_switches * (avg_cpu / 100 + 0.1) * 10),
            "L1-icache-load-misses": int(cpu_stats.interrupts * (avg_cpu / 100 + 0.1)),
            "branch-load-misses": int(cpu_stats.soft_interrupts * (avg_cpu / 100 + 0.1)),
            "node-load-misses": int(getattr(cpu_stats, 'syscalls', cpu_stats.ctx_switches) * (avg_cpu / 200 + 0.05)),
            "instructions": int(cpu_times.user * 1000000 + cpu_times.system * 500000),
        }

        # Disk I/O metrics
        disk_io = psutil.disk_io_counters()
        io_sample = {
            "rd_req": disk_io.read_count if disk_io else 0,
            "rd_bytes": disk_io.read_bytes if disk_io else 0,
            "wr_req": disk_io.write_count if disk_io else 0,
            "wr_bytes": disk_io.write_bytes if disk_io else 0,
            "flush_req": getattr(disk_io, 'read_merged_count', disk_io.read_count // 10) if disk_io else 0,
            "flush_total_times": disk_io.read_time if disk_io else 0,
            "rd_total_times": disk_io.read_time if disk_io else 0,
            "wr_total_times": disk_io.write_time if disk_io else 0,
        }

        # Add to buffers
        for event in HPC_EVENTS:
            self.hpc_buffer[event].append(hpc_sample[event])
        for event in IO_EVENTS:
            self.io_buffer[event].append(io_sample[event])

        return hpc_sample, io_sample

    def compute_features(self):
        """Compute statistical features from current buffer."""
        features = {}

        for event in HPC_EVENTS:
            values = list(self.hpc_buffer[event])
            if len(values) < 2:
                values = [0] * self.window_size
            features[f"{event}_mean"] = np.mean(values)
            features[f"{event}_median"] = np.median(values)
            features[f"{event}_std"] = np.std(values)
            features[f"{event}_iqr"] = np.percentile(values, 75) - np.percentile(values, 25)

        for event in IO_EVENTS:
            values = list(self.io_buffer[event])
            if len(values) < 2:
                values = [0] * self.io_window_size
            features[f"{event}_mean"] = np.mean(values)
            features[f"{event}_median"] = np.median(values)
            features[f"{event}_std"] = np.std(values)
            features[f"{event}_iqr"] = np.percentile(values, 75) - np.percentile(values, 25)

        return features

    def predict(self, features):
        """Run prediction using the trained model."""
        if not self.model_loaded:
            return None, None

        feature_cols = self.model_info.get("feature_columns", [])
        X = np.array([[features.get(col, 0) for col in feature_cols]])
        X_scaled = self.scaler.transform(X)

        prediction = self.model.predict(X_scaled)[0]
        try:
            probability = self.model.predict_proba(X_scaled)[0][1]
        except Exception:
            probability = float(prediction)

        return int(prediction), float(probability)

    def get_system_status(self):
        """Get current system status for dashboard."""
        cpu_percent = psutil.cpu_percent(interval=0.1, percpu=True)
        memory = psutil.virtual_memory()
        disk_io = psutil.disk_io_counters()
        # Use the system drive on Windows (e.g. C:\), fallback to '/' on Linux/Mac
        if os.name == 'nt':
            system_drive = os.path.splitdrive(os.path.abspath(__file__))[0] + '\\'
        else:
            system_drive = '/'
        disk_usage = psutil.disk_usage(system_drive)

        status = {
            "cpu": {
                "percent_per_core": cpu_percent,
                "average": np.mean(cpu_percent) if cpu_percent else 0,
                "count": psutil.cpu_count(),
            },
            "memory": {
                "total": memory.total,
                "used": memory.used,
                "percent": memory.percent,
                "available": memory.available,
            },
            "disk_io": {
                "read_count": disk_io.read_count if disk_io else 0,
                "write_count": disk_io.write_count if disk_io else 0,
                "read_bytes": disk_io.read_bytes if disk_io else 0,
                "write_bytes": disk_io.write_bytes if disk_io else 0,
            },
            "disk_usage": {
                "total": disk_usage.total,
                "used": disk_usage.used,
                "free": disk_usage.free,
                "percent": disk_usage.percent,
            },
            "timestamp": time.time(),
        }

        return status

    def run_detection_cycle(self):
        """Run one detection cycle: collect, compute, predict."""
        hpc_sample, io_sample = self.collect_sample()
        features = self.compute_features()
        prediction, probability = self.predict(features)

        result = {
            "timestamp": time.time(),
            "hpc_sample": hpc_sample,
            "io_sample": io_sample,
            "prediction": prediction,
            "probability": probability,
            "is_ransomware": prediction == 1 if prediction is not None else None,
        }

        self.detection_history.append(result)
        if len(self.detection_history) > 1000:
            self.detection_history = self.detection_history[-500:]

        return result
