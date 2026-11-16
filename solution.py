"""
Solution entry point called by eval.py.

The solution under research is the Go connectivity core in ./core (one binary,
`genadb`, acting as relay, device agent and desktop connect agent/CLI).
run_solution() builds it and returns the binary path. The research loop may
edit this file and anything under ./core.
"""
import os
import subprocess

HERE = os.path.dirname(os.path.abspath(__file__))


def run_solution():
    out = os.path.join(HERE, "build", "genadb")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    subprocess.run(["go", "build", "-o", out, "./cmd/genadb"], cwd=os.path.join(HERE, "core"),
                   check=True, timeout=120)
    return {"binary": out}
