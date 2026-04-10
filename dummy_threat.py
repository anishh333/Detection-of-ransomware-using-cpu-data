import os
import time

def simulate_io_spike():
    print(f"Simulating heavy I/O from PID {os.getpid()}...")
    try:
        with open("dummy_data.bin", "wb") as f:
            while True:
                f.write(os.urandom(1024 * 1024)) # Write 1MB chunks continuously
    except KeyboardInterrupt:
        print("Stopped.")
    finally:
        if os.path.exists("dummy_data.bin"):
            os.remove("dummy_data.bin")

if __name__ == "__main__":
    simulate_io_spike()
