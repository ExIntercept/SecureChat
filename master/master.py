# master_script.py
import subprocess
import time
import os
import signal
import sys

# Define the paths to the scripts
scripts = [
    "../server3/server3.py",
    "../server2/server2.py",
    "../server1/server1.py",
]

def start_scripts():
    processes = []
    for script in scripts:
        print(f"Starting {script}")
        process = subprocess.Popen(["python", script])
        processes.append(process)
        time.sleep(1)
    return processes

def stop_scripts(processes):
    for process in processes:
        print(f"Stopping process with PID {process.pid}")
        os.kill(process.pid, signal.SIGTERM)
    
    # Wait for all processes to finish
    for process in processes:
        process.wait()

if __name__ == "__main__":
    if len(sys.argv) != 2 or sys.argv[1] not in ["start", "stop"]:
        print("Usage: python master.py [start|stop]")
        sys.exit(1)

    if sys.argv[1] == "start":
        processes = start_scripts()
        print("All scripts started. Press Ctrl+C to stop.")
        try:
            # Keep the script running
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\nStopping all scripts...")
            stop_scripts(processes)
    elif sys.argv[1] == "stop":
        print("Stopping all scripts...")
        # Find and stop all running Python processes with the script names
        for script in scripts:
            script_name = os.path.basename(script)
            os.system(f"pkill -f {script_name}")
        print("All scripts stopped.")
