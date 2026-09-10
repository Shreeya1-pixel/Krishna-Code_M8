#!/usr/bin/env python3
"""
M8 CI Gate — CLI tool for pipeline integration.

Usage:
    python -m backend.scripts.ci_gate [--mode defended] [--url http://localhost:8000]

Exits 0 if gate passes, 1 if gate fails.
"""
import argparse
import json
import sys
import time
import urllib.request
import urllib.error


def main():
    parser = argparse.ArgumentParser(description="M8 CI Gate")
    parser.add_argument("--mode", default="defended", choices=["defended", "vulnerable"])
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--timeout", type=int, default=300, help="Max wait time in seconds")
    args = parser.parse_args()

    base = args.url.rstrip("/")

    print(f"🛡 M8 CI Gate")
    print(f"   Mode: {args.mode}")
    print(f"   Backend: {base}")
    print()

    # Health check
    try:
        with urllib.request.urlopen(f"{base}/health", timeout=10) as resp:
            health = json.loads(resp.read())
            print(f"✓ Backend healthy: {health.get('version', 'N/A')}")
    except Exception as e:
        print(f"✗ Backend not reachable: {e}")
        sys.exit(1)

    # Trigger assessment run
    print(f"\nStarting {args.mode} assessment...")
    payload = json.dumps({"mode": args.mode, "suite_type": "suite"}).encode()
    req = urllib.request.Request(
        f"{base}/assessment/run",
        data=payload,
        headers={"Content-Type": "application/json", "Accept": "text/event-stream"},
    )

    run_id = None
    gate_status = None
    asr = None
    succeeded = 0
    total = 0

    try:
        with urllib.request.urlopen(req, timeout=args.timeout) as resp:
            for line in resp:
                line = line.decode("utf-8").strip()
                if line.startswith("data:"):
                    try:
                        data = json.loads(line[5:].strip())
                        event_type = None
                    except:
                        continue
                elif line.startswith("event:"):
                    event_type = line[6:].strip()
                    continue
                else:
                    continue

                if event_type == "done":
                    run_id = data.get("run_id")
                    asr = data.get("asr", 0)
                    succeeded = data.get("succeeded", 0)
                    total = data.get("total", 0)
                    gate_status = data.get("gate_status", "N/A")
                elif event_type == "attack_result":
                    r = data.get("result", "?")
                    icon = "✓" if r == "BLOCKED" else "✗" if r == "SUCCEEDED" else "~"
                    print(f"  {icon} {data.get('attack_id', '?')} [{data.get('category', '?')}]: {r}")

    except Exception as e:
        print(f"✗ Assessment failed: {e}")
        sys.exit(1)

    print(f"\n── Results ──────────────────────────────")
    print(f"  Run ID:    {run_id}")
    print(f"  Total:     {total}")
    print(f"  Succeeded: {succeeded}")
    print(f"  ASR:       {asr:.1%}" if asr is not None else "  ASR: N/A")
    print(f"  Gate:      {gate_status}")

    # Get workflow result
    if run_id:
        try:
            with urllib.request.urlopen(f"{base}/workflow/runs/{run_id}", timeout=10) as resp:
                wf = json.loads(resp.read())
                reasons = wf.get("gate_reasons", [])
                for reason in reasons:
                    print(f"  → {reason}")
        except:
            pass

    print()
    if gate_status == "FAIL" or (asr is not None and asr > 0.20):
        print("❌ CI GATE FAILED — Release blocked")
        sys.exit(1)
    else:
        print("✅ CI GATE PASSED — Safe to release")
        sys.exit(0)


if __name__ == "__main__":
    main()
