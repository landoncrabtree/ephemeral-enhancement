import os
import re
import subprocess
import sys
import time

from stages.mcrypt_registry import list_mcrypt_stages

stages = list_mcrypt_stages()

pipelines = [
    ("b64>{stage}", "Pipeline 1"),
    ("columnar>b64>{stage}", "Pipeline 2"),
    ("double_columnar>b64>{stage}", "Pipeline 3"),
]

results = {}

# Make sure `run_pipeline.py` and `test_dict.txt` are in the cwd
if not os.path.exists("run_pipeline.py"):
    raise FileNotFoundError("run_pipeline.py not found in current directory")
if not os.path.exists("test_dict.txt"):
    raise FileNotFoundError("test_dict.txt not found in current directory")

for pipe_template, label in pipelines:
    hits_total = 0
    t0 = time.time()

    for i, stage in enumerate(stages, 1):
        pipeline = pipe_template.replace("{stage}", stage)
        cmd = [
            sys.executable,
            "run_pipeline.py",
            "--pipeline",
            pipeline,
            "--dictionary",
            "dicts/zombies.txt",
            "--vary-case",
            "--threshold",
            "0.7",
            "--workers",
            "4",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout + result.stderr

        # Parse hits from [done] line: "hits=N"
        done_match = re.search(r"hits=(\d+)", output)
        n_hits = int(done_match.group(1)) if done_match else 0
        print(f"[{i:2d}/{len(stages)}] {pipeline:40s} {n_hits} hits")

        hits_total += n_hits
        elapsed = time.time() - t0

    elapsed = time.time() - t0
    results[label] = {"hits": hits_total, "duration": elapsed}

print("  SUMMARY")
for label, r in results.items():
    print(f"  {label}: {r['hits']} hits in {r['duration'] / 60:.1f} min")
