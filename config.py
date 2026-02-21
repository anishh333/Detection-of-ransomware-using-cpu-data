"""
Configuration file for Ransomware Detection System
Based on: "Detection of Ransomware Attacks Using Processor and Disk Usage Data"
by Kumar Thummapudi, Palden Lama, and Rajendra V. Boppana (IEEE Access, 2023)
"""

import os

# --- Project Paths ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODEL_DIR = os.path.join(BASE_DIR, "models")
STATIC_DIR = os.path.join(BASE_DIR, "static")
TEMPLATE_DIR = os.path.join(BASE_DIR, "templates")

# Create directories if they don't exist
for d in [DATA_DIR, MODEL_DIR, STATIC_DIR, TEMPLATE_DIR]:
    os.makedirs(d, exist_ok=True)

# --- HPC Events (5 selected from the paper) ---
HPC_EVENTS = [
    "LLC-stores",
    "L1-icache-load-misses",
    "branch-load-misses",
    "node-load-misses",
    "instructions"
]

# --- Disk I/O Events (8 events from domblkstats) ---
IO_EVENTS = [
    "rd_req",       # Read requests
    "rd_bytes",     # Read bytes
    "wr_req",       # Write requests
    "wr_bytes",     # Write bytes
    "flush_req",    # Flush requests
    "flush_total_times",  # Flush total time
    "rd_total_times",     # Read total time
    "wr_total_times"      # Write total time
]

# --- Statistical Features (per the paper) ---
STAT_FEATURES = ["mean", "median", "std", "iqr"]

# --- Sampling Configuration (per the paper) ---
HPC_SAMPLING_INTERVAL_MS = 5      # 5 ms for HPC events
IO_SAMPLING_INTERVAL_MS = 20      # 20 ms for disk I/O events
HPC_SAMPLES_PER_INSTANCE = 40     # 40 samples per HPC instance
IO_SAMPLES_PER_INSTANCE = 10      # 10 samples per I/O instance
INSTANCE_DURATION_MS = 200         # Each instance = 200 ms
TOTAL_INSTANCES_PER_TRACE = 300    # 300 instances per trace (~60s)

# --- ML Classifiers ---
CLASSIFIERS = [
    "Random Forest",
    "SVM",
    "Decision Tree",
    "kNN",
    "XGBoost",
    "DNN",
    "LSTM"
]

# --- Model Configuration ---
CLASSIFICATION_THRESHOLD = 0.5
RANDOM_STATE = 42
TEST_SIZE = 0.3

# --- Workload Types (from the paper) ---
WORKLOAD_TYPES = [
    "BL.0",  # Base Load: no user activities
    "CL.0",  # CPU-intensive Load: ~10 apps
    "CL.1",  # CPU-intensive variant 1
    "CL.2",  # CPU-intensive variant 2
    "NL.0",  # Network-intensive Load: 30+ apps
    "NL.1",  # Network-intensive variant 1
]

# --- Ransomware Families (from the paper) ---
RANSOMWARE_FAMILIES = {
    "Sodinokibi": ["133b", "4f7b"],
    "Netwalker": ["17d1"],
    "Ryuk": ["7fae"],
    "Conti": ["a1b2"],
    "LockBit": ["c3d4"],
    "DarkSide": ["e5f6"],
    "BlackMatter": ["g7h8"],
    "REvil": ["i9j0"],
    "Maze": ["k1l2"],
    "WannaCry": ["m3n4"],
}

# --- Benign Applications ---
BENIGN_APPS = ["7zip", "aesCrypt", "sDelete", "dryRun"]

# --- Flask Configuration ---
FLASK_HOST = "127.0.0.1"
FLASK_PORT = 5000
DEBUG = True
