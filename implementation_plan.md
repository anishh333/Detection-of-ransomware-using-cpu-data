# Fixing Architectural Flaws & Missing Benchmarks

Here is the detailed, step-by-step technical plan to overhaul the system architecture and fix the heuristics, excluding any database/persistence implementations.

## 1. Overcoming the "Browser Tab" Flaw (Background Threading)

Currently, the Flask server only calls `monitor.run_detection_cycle()` when the web browser specifically asks it to via `/api/detect`. 

**The Solution: Dedicated Server Daemon**
We must detach the detection engine from the Web API. The monitor should run continuously in the background, independently of any web requests.

#### [MODIFY] [monitor.py](file:///d:/Major_project/monitor.py)
- **Add a Background Loop**: I will add a `start_background_monitoring()` method to the `SystemMonitor` class. This method will spawn a `threading.Thread`.
- **The Thread Logic**: Inside the thread, a `while self.is_monitoring:` loop will continuously run `self.run_detection_cycle()` and then specifically `time.sleep(0.2)` (to match your 200ms `INSTANCE_DURATION_MS`).

#### [MODIFY] [app.py](file:///d:/Major_project/app.py)
- **Auto-Start**: When `app.py` starts up, it will immediately call `monitor.start_background_monitoring()`. 
- **Decouple API**: I will rewrite the `/api/detect` route. Instead of running a detection cycle synchronously and forcing the browser to wait, the route will simply instantly return the *last completed result* from `monitor.detection_history[-1]`. 

## 2. Overcoming the Threat Attribution Flaw (The Cumulative Bug)

**The Hidden Bug:** I looked closely at how `_identify_threat()` calculates Disk I/O. It uses `p.info['io_counters'].write_bytes`. However, in `psutil`, `write_bytes` represents the **total bytes written since the application was first opened**, NOT the current spike in the last 200ms! This means your code will accidentally target innocent programs that have been running for a long time (like Chrome or Discord) rather than the actual ransomware virus.

**The Solution: The Delta Tracking Method**
To find the real ransomware, we must measure the *speed* of the I/O, not the total volume.

#### [MODIFY] [monitor.py](file:///d:/Major_project/monitor.py)
- **State Dictionary**: I will create a dictionary inside `SystemMonitor` called `self.process_io_state = {}` to map `PID -> previous_write_bytes`.
- **Calculate Delta**: Inside `_identify_threat()`, instead of looking at the raw `write_bytes`, we will calculate `current_write_bytes - previous_write_bytes`. This gives us the exact amount of data encrypted/written in the exact 200ms window where the alert was triggered.
- **Improved Heuristic**: The process with the absolute highest `write_bytes_delta` in that specific 200ms window will be correctly identified as the threat. 

## 3. Creating the Stress & False Positive Benchmarks

To prove this new architecture works and doesn't crash your computer, we need localized stress tests.

#### [NEW] [stress_validator.py](file:///d:/Major_project/stress_validator.py)
I will write a new benchmark script containing two critical tests:

**Test A: System Overhead Monitor**
- It will start your new Background Thread architecture and monitor *your python script itself* for 60 seconds.
- It will output exactly how much CPU % and Memory your background detection agent consumes. If it's over ~5%, we will need to optimize the `psutil` polling logic.

**Test B: The False Positive Simulator**
- It will execute a function that creates thousands of tiny files and zips them heavily (mimicking standard developer behavior or benign high-I/O loads).
- We will observe if your ML model accidentally triggers a ransomware alert. If it does, it proves the model needs retraining on heavier `NL.0` (Network Load) benign datasets.

## User Review Required

> [!IMPORTANT]  
> Please review this plan. Fixing the **Background Thread** and the **Cumulative I/O Bug** are highly recommended to make this project function as a real security tool. 
> Should I proceed with executing these exact code changes?
