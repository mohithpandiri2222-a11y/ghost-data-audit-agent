"""
HackerRank Orchestrate (October 2026) — Ghost Data Still Exists
Main Solution Entry Point

Usage:
    python code/main.py [--requests dataset/deletion_requests.csv] [--output output.csv]
"""

import argparse
import csv
import sys
import time
from pathlib import Path

# Ensure repository root is at the head of sys.path so 'code' resolves to repo package
repo_root = Path(__file__).resolve().parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from code.config import DATASET_DIR, OUTPUT_PATH, REPO_ROOT
from code.planner import AuditPlanner, load_deletion_requests


def main() -> int:
    parser = argparse.ArgumentParser(description="Ghost Data Audit Agent - Main Entry Point")
    parser.add_argument(
        "--requests",
        type=Path,
        default=DATASET_DIR / "deletion_requests.csv",
        help="Path to deletion_requests.csv (default: dataset/deletion_requests.csv)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=OUTPUT_PATH,
        help="Path to output.csv (default: output.csv at repo root)",
    )
    args = parser.parse_args()

    requests_path = args.requests.resolve()
    output_path = args.output.resolve()

    if not requests_path.is_file():
        print(f"Error: Requests file not found at {requests_path}", file=sys.stderr)
        return 1

    print(f"Loading deletion requests from: {requests_path}")
    start_time = time.time()

    planner = AuditPlanner(requests_path=requests_path)
    requests = load_deletion_requests(requests_path)
    total_requests = len(requests)
    print(f"Loaded {total_requests} requests. Running audit pipeline...")

    results = planner.audit_all(requests)
    elapsed = time.time() - start_time

    # Tally statuses
    status_counts = {"COMPLETE": 0, "INCOMPLETE": 0, "NOT_APPLICABLE": 0}
    for r in results:
        status_counts[r.deletion_status] = status_counts.get(r.deletion_status, 0) + 1

    # Write output.csv
    print(f"Writing {len(results)} audited rows to: {output_path}")
    fieldnames = ["case_id", "deletion_status", "steps_json"]
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, lineterminator="\n")
        writer.writeheader()
        for r in results:
            writer.writerow(r.to_row())

    print(f"\nAudit complete in {elapsed:.2f}s:")
    print(f"  Total processed: {total_requests}")
    print(f"  COMPLETE:        {status_counts.get('COMPLETE', 0)}")
    print(f"  INCOMPLETE:      {status_counts.get('INCOMPLETE', 0)}")
    print(f"  NOT_APPLICABLE:  {status_counts.get('NOT_APPLICABLE', 0)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
