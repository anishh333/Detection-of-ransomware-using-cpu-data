"""
Flask Web Application - Ransomware Detection Dashboard
Main application file with API endpoints and web routes.
"""

from flask import Flask, render_template, jsonify, request
import os
import sys
import json
import time
import threading

from config import (
    FLASK_HOST, FLASK_PORT, DEBUG, MODEL_DIR, DATA_DIR,
    TEMPLATE_DIR, STATIC_DIR, HPC_EVENTS, IO_EVENTS, BASE_DIR
)
from monitor import SystemMonitor

# Ensure project root is on sys.path so local modules can be imported
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

app = Flask(__name__,
            template_folder=TEMPLATE_DIR,
            static_folder=STATIC_DIR)

# Initialize system monitor
monitor = SystemMonitor()


# ==================== WEB ROUTES ====================

@app.route("/")
def index():
    """Main dashboard page."""
    return render_template("index.html")


@app.route("/training")
def training_page():
    """Model training and results page."""
    return render_template("training.html")


@app.route("/monitoring")
def monitoring_page():
    """Live monitoring page."""
    return render_template("monitoring.html")


@app.route("/about")
def about_page():
    """About/documentation page."""
    return render_template("about.html")


# ==================== API ENDPOINTS ====================

@app.route("/api/system-status")
def api_system_status():
    """Get current system status."""
    try:
        status = monitor.get_system_status()
        return jsonify({"success": True, "data": status})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/detect")
def api_detect():
    """Run one detection cycle."""
    try:
        result = monitor.run_detection_cycle()
        return jsonify({"success": True, "data": result})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/model-info")
def api_model_info():
    """Get trained model information."""
    try:
        info_path = os.path.join(MODEL_DIR, "model_info.json")
        if os.path.exists(info_path):
            with open(info_path, "r") as f:
                info = json.load(f)
            return jsonify({"success": True, "data": info})
        else:
            return jsonify({"success": False, "error": "Model not trained yet"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/model-results")
def api_model_results():
    """Get all model training results."""
    try:
        results_path = os.path.join(MODEL_DIR, "all_results.json")
        if os.path.exists(results_path):
            with open(results_path, "r") as f:
                results = json.load(f)
            return jsonify({"success": True, "data": results})
        else:
            return jsonify({"success": False, "error": "Models not trained yet"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/train", methods=["POST"])
def api_train():
    """Trigger model training."""
    try:
        from data_generator import generate_dataset
        from ml_models import train_and_save

        # Generate data if not exists
        dataset_path = os.path.join(DATA_DIR, "ransomware_dataset.csv")
        if not os.path.exists(dataset_path):
            generate_dataset(num_rounds=3)  # Fewer rounds for speed

        results = train_and_save()

        # Reload model in monitor by creating a new instance
        global monitor
        monitor = SystemMonitor()

        return jsonify({"success": True, "message": "Training complete"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)})


@app.route("/api/detection-history")
def api_detection_history():
    """Get detection history."""
    limit = request.args.get("limit", 50, type=int)
    history = monitor.detection_history[-limit:]
    return jsonify({"success": True, "data": history})


@app.route("/api/hpc-events")
def api_hpc_events():
    """Get HPC event descriptions."""
    return jsonify({"success": True, "data": HPC_EVENTS})


@app.route("/api/io-events")
def api_io_events():
    """Get I/O event descriptions."""
    return jsonify({"success": True, "data": IO_EVENTS})


# ==================== MAIN ====================

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  RANSOMWARE DETECTION SYSTEM")
    print("  Based on: Thummapudi et al. (IEEE Access, 2023)")
    print("=" * 60)
    print(f"\n  Dashboard: http://{FLASK_HOST}:{FLASK_PORT}")
    print(f"  Model loaded: {monitor.model_loaded}")
    print("=" * 60 + "\n")

    app.run(host=FLASK_HOST, port=FLASK_PORT, debug=DEBUG)
