# master_script.py
import subprocess
import time

# Define the paths to the scripts
scripts = [
    "../server3/server3.py",
    "../server2/server2.py",
    "../server1/server1.py",

]

# Run each script
for script in scripts:
    print(f"Running {script}")
    subprocess.Popen(["python", script])
    time.sleep(1)
