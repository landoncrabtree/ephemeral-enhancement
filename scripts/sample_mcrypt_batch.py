"""Run pipelines 1-3 from ATTEMPTS.md against all mcrypt stages."""
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

for pipe_template, label in pipelines:
    print(f"\n{'='*60}")
    print(f"  {label}: {pipe_template}")
    print(f"{'='*60}", flush=True)
    
    hits_total = 0
    t0 = time.time()
    
    for i, stage in enumerate(stages, 1):
        pipeline = pipe_template.replace("{stage}", stage)
        cmd = [
            sys.executable, "run_pipeline.py",
            "--pipeline", pipeline,
            "--dictionary", "test_dict.txt",
            "--vary-case",
            "--threshold", "1.0",
            "--workers", "4",
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True)
        output = result.stdout + result.stderr
        
        # Parse hits from [done] line: "hits=N"
        done_match = re.search(r'hits=(\d+)', output)
        n_hits = int(done_match.group(1)) if done_match else 0
        
        # Capture hit lines (score lines starting with a float)
        hit_lines = [l for l in output.strip().split('\n') 
                     if re.match(r'^\d+\.\d+\s', l)]
        
        hits_total += n_hits
        
        status = f"HIT {n_hits}" if n_hits > 0 else "0"
        elapsed = time.time() - t0
        print(f"  [{i:2d}/{len(stages)}] {pipeline:40s} {status}  ({elapsed:.0f}s)", flush=True)
        
        if n_hits > 0:
            for l in hit_lines[:5]:  # show up to 5 hits
                print(f"    >>> {l.strip()}", flush=True)
    
    elapsed = time.time() - t0
    results[label] = {"hits": hits_total, "duration": elapsed}
    print(f"\n  {label} complete: {hits_total} hits in {elapsed:.0f}s ({elapsed/60:.1f} min)", flush=True)

print(f"\n{'='*60}")
print("  SUMMARY")
print(f"{'='*60}")
for label, r in results.items():
    print(f"  {label}: {r['hits']} hits in {r['duration']/60:.1f} min")
