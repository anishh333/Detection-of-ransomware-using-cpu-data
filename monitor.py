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
import ctypes
import struct
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
        self.monitor_thread = None
        self.process_io_state = {}
        self.process_io_delta = {}
        self.detection_history = []
        
        # New Enterprise Fields
        self.ignored_pids = set()
        self.auto_kill_enabled = False
        
        # Initialize Canary Handler
        try:
            from canary_manager import CanaryManager
            self.canary_manager = CanaryManager(self)
        except ImportError:
            self.canary_manager = None

    def start_background_monitoring(self):
        if not self.is_monitoring:
            self.is_monitoring = True
            if self.canary_manager:
                self.canary_manager.start()
            import threading
            self.monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
            self.monitor_thread.start()

    def stop_background_monitoring(self):
        self.is_monitoring = False
        if self.monitor_thread:
            self.monitor_thread.join(timeout=1.0)
        if hasattr(self, 'canary_manager') and self.canary_manager:
            self.canary_manager.stop()
    def _monitor_loop(self):
        while self.is_monitoring:
            self.run_detection_cycle()
            time.sleep(self.sampling_interval)

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

    def _identify_threat(self):
        """Scans running processes to identify the likely ransomware process based on CPU/Disk I/O."""
        highest_cpu = 0
        highest_io = 0
        suspect = None
        
        # System whitelist
        protected_procs = {
            'system', 'idle', 'smss.exe', 'csrss.exe', 'wininit.exe', 
            'services.exe', 'lsass.exe', 'lsm.exe', 'svchost.exe', 
            'explorer.exe', 'winlogon.exe', 'spoolsv.exe', 'taskmgr.exe'
        }

        whitelisted_procs = {
            'brave.exe', 'chrome.exe', 'msedge.exe', 'firefox.exe', 'opera.exe',
            'code.exe', 'idea64.exe', 'pycharm64.exe', 'devenv.exe', 'webstorm.exe',
            'python.exe', 'pythonw.exe', 'node.exe', 'java.exe', 'javaw.exe',
            'docker.exe', 'vmmem', 'discord.exe', 'slack.exe', 'teams.exe', 'zoom.exe',
            'antigravity.exe', 'language_server_windows_x64.exe', 'rg.exe', 'cmd.exe', 'powershell.exe'
        }
        protected_procs.update(whitelisted_procs)

        initial_state = {}
        for p in psutil.process_iter(['pid', 'io_counters']):
            try:
                io_write = p.info['io_counters'].write_bytes if p.info.get('io_counters') else 0
                initial_state[p.info['pid']] = io_write
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                pass

        time.sleep(0.2)

        try:
            for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'io_counters', 'username', 'exe']):
                try:
                    pid = p.info['pid']
                    if pid in self.ignored_pids:
                        continue
                        
                    name = p.info['name'].lower()
                    
                    # Absolute Path Verification
                    path = p.info.get('exe', "") or ""
                    lower_path = path.lower()
                    
                    if name in protected_procs:
                        # Only trust it if it lives in a standard trustworthy directory
                        if "windows\\system32" in lower_path or "program files" in lower_path or "appdata\\local\\programs" in lower_path:
                            continue
                        
                    username = p.info.get('username')
                    if username and ('SYSTEM' in username or 'AUTHORITY' in username):
                         continue

                    cpu = p.info['cpu_percent'] or 0
                    
                    io_write = p.info['io_counters'].write_bytes if p.info.get('io_counters') else 0
                    prev_write = initial_state.get(pid, io_write)
                    io_delta = io_write - prev_write
                    
                    if cpu > highest_cpu or io_delta > highest_io:
                        highest_cpu = cpu
                        highest_io = io_delta
                        suspect = p
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
        except Exception as e:
            print(f"Error scanning processes: {e}")

        if not suspect:
            return {"name": "Unknown", "pid": -1, "path": "Unknown", "category": "General Anomaly", "is_signed": False}

        try:
            path = suspect.exe()
        except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
            path = "Access Denied"

        is_signed = False
        if path and path != "Access Denied":
             lower_path = path.lower()
             if "windows\\system32" in lower_path or "microsoft" in lower_path or "program files" in lower_path:
                 if "appdata" not in lower_path and "temp" not in lower_path:
                     is_signed = True
                     
        category = "High Processor/IO Anomaly"
        if highest_io > 10 * 1024 * 1024:  # > 10MB write in this tick
            category = "High Disk Write Anomaly"
        elif highest_cpu > 50:
            category = "High CPU Utilization Anomaly"

        return {
            "name": suspect.info['name'],
            "pid": suspect.info['pid'],
            "path": path,
            "category": category,
            "is_signed": is_signed,
            "username": suspect.info.get('username', 'Unknown')
        }

    def run_detection_cycle(self):
        """Run one detection cycle: collect, compute, predict."""
        hpc_sample, io_sample = self.collect_sample()
        features = self.compute_features()
        prediction, probability = self.predict(features)
        
        # Require higher confidence (> 0.85) to heavily reduce false positives
        is_ransomware = (prediction == 1 and probability > 0.85) if prediction is not None else None
        
        # Identify threat if ransomware detected
        threat_info = None
        if is_ransomware:
            threat_info = self._identify_threat()
            
            # Autonomous Kill Logic
            if self.auto_kill_enabled and probability >= 0.95 and threat_info['pid'] != -1 and threat_info['pid'] not in self.ignored_pids:
                try:
                    print(f"[!] AUTONOMOUS KILL ENGAGED: Terminating {threat_info['name']} (PID: {threat_info['pid']})")
                    p = psutil.Process(threat_info['pid'])
                    p.terminate()
                    threat_info["killed_by_ai"] = True
                except Exception as e:
                    print(f"[-] Auto-Kill failed: {e}")

        result = {
            "timestamp": time.time(),
            "hpc_sample": hpc_sample,
            "io_sample": io_sample,
            "prediction": prediction,
            "probability": probability,
            "is_ransomware": is_ransomware,
            "threat_info": threat_info
        }

        self.detection_history.append(result)
        if len(self.detection_history) > 1000:
            self.detection_history = self.detection_history[-500:]

        return result
