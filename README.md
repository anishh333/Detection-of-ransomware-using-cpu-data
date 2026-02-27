# 🛡️ RansomShield — Ransomware Detection Using CPU & Disk Usage Data

A machine-learning-based ransomware detection system that analyses **Hardware Performance Counter (HPC)** and **Disk I/O** metrics to identify ransomware activity in real time.

> **Based on:** *"Detection of Ransomware Attacks Using Processor and Disk Usage Data"*
> — Kumar Thummapudi, Palden Lama & Rajendra V. Boppana (IEEE Access, 2023)

---

## 📑 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Project Structure](#project-structure)
- [Tech Stack](#tech-stack)
- [Installation](#installation)
- [Usage](#usage)
- [ML Models & Methodology](#ml-models--methodology)
- [API Endpoints](#api-endpoints)
- [Screenshots](#screenshots)
- [License](#license)

---

## Overview

RansomShield monitors system-level processor and disk activity to detect ransomware attacks. It extracts statistical features (mean, median, standard deviation, IQR) from five HPC events and eight disk I/O events, then classifies the activity using trained ML models. A Flask web dashboard provides real-time monitoring, model training controls, and detection history.

---

## Features

| Category | Details |
|---|---|
| **Real-Time Monitoring** | Continuously collects CPU & Disk I/O metrics via `psutil` |
| **Multi-Model Training** | Trains & compares 5 classifiers — Random Forest, SVM, Decision Tree, kNN, XGBoost |
| **Three Detection Modes** | HPC-only, I/O-only, and Integrated (HPC + I/O) |
| **Web Dashboard** | Interactive Flask app with live charts, training controls, and detection alerts |
| **Simulated Dataset** | Generates realistic ransomware vs. benign data based on the paper's methodology |

---

## Project Structure

```
Major_project/
├── app.py                 # Flask web application & API endpoints
├── config.py              # Central configuration (events, paths, ML params)
├── data_generator.py      # Simulates HPC & I/O data for training
├── ml_models.py           # ML model training, evaluation & export
├── monitor.py             # Real-time system monitor using psutil
├── requirements.txt       # Python dependencies
│
├── data/
│   └── data_file.csv      # Generated training dataset
│
├── models/                # Generated after training
│   ├── best_model.pkl     # Serialised best classifier
│   ├── scaler.pkl         # Fitted StandardScaler
│   ├── model_info.json    # Best model metadata & feature list
│   └── all_results.json   # Evaluation metrics for all models
│
├── templates/             # Jinja2 HTML templates
│   ├── index.html         # Main dashboard
│   ├── training.html      # Training & results page
│   ├── monitoring.html    # Live monitoring page
│   └── about.html         # Documentation / about page
│
└── static/                # Frontend assets
    ├── style.css          # Global stylesheet
    ├── dashboard.js       # Dashboard interactivity
    ├── monitoring.js      # Live monitoring logic
    └── training.js        # Training page logic
```

---

## Tech Stack

- **Backend:** Python 3.8+, Flask
- **ML / Data:** scikit-learn, XGBoost, NumPy, Pandas
- **System Monitoring:** psutil
- **Frontend:** HTML5, CSS3, Vanilla JavaScript
- **Visualisation:** Matplotlib, Seaborn (optional, for plots)

---

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/<your-username>/Detection-of-ransomware-using-cpu-data.git
cd Detection-of-ransomware-using-cpu-data
```

### 2. Create a Virtual Environment

```bash
python -m venv myenv

# Windows
myenv\Scripts\activate

# macOS / Linux
source myenv/bin/activate
```

### 3. Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

### Generate Training Data

```bash
python data_generator.py
```

This creates `data/data_file.csv` containing simulated HPC and I/O traces for 10 ransomware families and 4 benign applications across 6 workload types.

### Train Models

```bash
python ml_models.py
```

Trains all 5 classifiers across three modes (HPC-only, I/O-only, Integrated). After training, the following files are generated inside the `models/` directory:

| File | Description |
|---|---|
| `best_model.pkl` | Serialised best-performing classifier |
| `scaler.pkl` | Fitted `StandardScaler` for feature normalisation |
| `model_info.json` | Metadata for the best model (classifier name, features, metrics) |
| `all_results.json` | Evaluation results for every classifier × mode combination |

### Launch the Dashboard

```bash
python app.py
```

Open your browser and navigate to **http://127.0.0.1:5000**.

| Page | URL | Description |
|---|---|---|
| Dashboard | `/` | System overview & quick status |
| Training | `/training` | Train models & view evaluation metrics |
| Monitoring | `/monitoring` | Live ransomware detection feed |
| About | `/about` | Project documentation & methodology |

---

## ML Models & Methodology

### Feature Engineering

The system collects two categories of telemetry data and computes **4 statistical features** (mean, median, std, IQR) for each event:

**HPC Events (5):**
`LLC-stores` · `L1-icache-load-misses` · `branch-load-misses` · `node-load-misses` · `instructions`

**Disk I/O Events (8):**
`rd_req` · `rd_bytes` · `wr_req` · `wr_bytes` · `flush_req` · `flush_total_times` · `rd_total_times` · `wr_total_times`

> **Total features:** (5 HPC + 8 I/O) × 4 stats = **52 features** (Integrated mode)

### Classifiers

| # | Classifier | Library |
|---|---|---|
| 1 | Random Forest | scikit-learn |
| 2 | SVM | scikit-learn |
| 3 | Decision Tree | scikit-learn |
| 4 | k-Nearest Neighbors | scikit-learn |
| 5 | XGBoost | xgboost |

### Evaluation Metrics

Models are evaluated using: **Balanced Accuracy**, **F1-Score**, **Precision**, **Recall**, **FPR**, **FNR**, and **ROC-AUC**.

### Detection Modes

| Mode | Features Used | Feature Count |
|---|---|---|
| **HPC-only** | 5 HPC events × 4 stats | 20 |
| **I/O-only** | 8 I/O events × 4 stats | 32 |
| **Integrated** | All HPC + I/O events × 4 stats | 52 |

---

## API Endpoints

| Method | Endpoint | Description |
|---|---|---|
| `GET` | `/api/system-status` | Current CPU, memory & disk metrics |
| `GET` | `/api/detect` | Run one detection cycle |
| `GET` | `/api/model-info` | Trained model metadata |
| `GET` | `/api/model-results` | All classifier evaluation results |
| `POST` | `/api/train` | Trigger model training |
| `GET` | `/api/detection-history` | Recent detection results |
| `GET` | `/api/hpc-events` | List of HPC event names |
| `GET` | `/api/io-events` | List of I/O event names |

---

## Screenshots

> _Run the application and visit `http://127.0.0.1:5000` to explore the dashboard._

---

## License

This project is developed for academic purposes based on the referenced IEEE Access paper.

---

<p align="center">
  Built with ❤️ for cybersecurity research
</p>
