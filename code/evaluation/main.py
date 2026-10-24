"""
HackerRank Orchestrate (October 2026) — Ghost Data Still Exists
Evaluation and Validation Pipeline

Validates output.csv against all specification and contract constraints:
1. Exact column headers and row counts
2. Valid statuses and strict JSON serialization
3. Step numbering, schema, and phase ordering
4. Dual temporal admissibility of all cited evidence IDs
5. Invariant checking: COMPLETE non-empty proof, INCOMPLETE empty future evidence IDs, NOT_APPLICABLE []
6. Public sample benchmark evaluation

Usage:
    python code/evaluation/main.py [--output output.csv] [--samples dataset/sample_output.csv]
"""

import argparse
import csv
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Set, Tuple

# Ensure repository root is on sys.path
repo_root = Path(__file__).resolve().parent.parent.parent
if str(repo_root) not in sys.path:
    sys.path.insert(0, str(repo_root))

from code.config import (
    DATASET_DIR,
    DELETION_REQUESTS_PATH,
    EVIDENCE_FILES_PATH,
    FINDING_OPERATIONS,
    REMEDIATION_OPERATIONS,
    VERIFICATION_OPERATIONS,
    ALLOWED_OPERATION_STATES,
    OUTPUT_PATH,
    SAMPLE_DELETION_REQUESTS_PATH,
    SAMPLE_OUTPUT_PATH,
    load_evidence_manifest,
    parse_iso_timestamp,
)
from code.planner import (
    AuditPlanner,
    STATUS_COMPLETE,
    STATUS_INCOMPLETE,
    STATUS_NOT_APPLICABLE,
    load_deletion_requests,
)

VALID_FINDING_OPERATIONS = {op for op, _ in FINDING_OPERATIONS}
VALID_REMEDIATION_OPERATIONS = {op for op, _ in REMEDIATION_OPERATIONS}
VALID_VERIFICATION_OPERATIONS = {op for op, _ in VERIFICATION_OPERATIONS}
ALL_VALID_OPERATIONS = set(ALLOWED_OPERATION_STATES.keys())
VALID_STATES = set(ALLOWED_OPERATION_STATES.values())
VALID_STATUSES = {STATUS_COMPLETE, STATUS_INCOMPLETE, STATUS_NOT_APPLICABLE}
VALID_PHASES = {"FINDING", "REMEDIATION", "VERIFICATION"}
PHASE_RANK = {"FINDING": 0, "REMEDIATION": 1, "VERIFICATION": 2}


def validate_output_csv(output_path: Path, requests_path: Path) -> Tuple[bool, List[str], Dict[str, Any]]:
    """Validates the output.csv file against all specification rules."""
    errors: List[str] = []
    stats: Dict[str, Any] = {
        "total_rows": 0,
        "complete_count": 0,
        "incomplete_count": 0,
        "not_applicable_count": 0,
        "total_steps": 0,
        "finding_steps": 0,
        "remediation_steps": 0,
        "verification_steps": 0,
        "unique_evidence_cited": set(),
    }

    if not output_path.is_file():
        return False, [f"Output file missing: {output_path}"], stats

    manifest = load_evidence_manifest(EVIDENCE_FILES_PATH)
    requests = {r.case_id: r for r in load_deletion_requests(requests_path)}

    with open(output_path, "r", encoding="utf-8") as f:
        reader = csv.reader(f)
        try:
            header = next(reader)
        except StopIteration:
            return False, ["Output CSV is empty."], stats

        expected_header = ["case_id", "deletion_status", "steps_json"]
        if header != expected_header:
            errors.append(f"Invalid header: expected {expected_header}, got {header}")

        seen_cases: Set[str] = set()
        prev_case_id = ""

        for row_idx, row in enumerate(reader, start=2):
            if len(row) != 3:
                errors.append(f"Row {row_idx}: expected 3 columns, got {len(row)}")
                continue

            case_id, status, steps_raw = row[0].strip(), row[1].strip(), row[2].strip()
            stats["total_rows"] += 1

            # Case ordering & uniqueness
            if not case_id:
                errors.append(f"Row {row_idx}: empty case_id")
                continue

            if case_id in seen_cases:
                errors.append(f"Row {row_idx}: duplicate case_id '{case_id}'")
            seen_cases.add(case_id)

            if prev_case_id and case_id < prev_case_id:
                errors.append(f"Row {row_idx}: case_id '{case_id}' out of sort order (prev: '{prev_case_id}')")
            prev_case_id = case_id

            if case_id not in requests:
                errors.append(f"Row {row_idx}: unknown case_id '{case_id}' not in deletion requests")
                continue

            case_req = requests[case_id]
            audit_at = case_req.audit_at

            # Status validation
            if status not in VALID_STATUSES:
                errors.append(f"Row {row_idx} ({case_id}): invalid status '{status}'")
                continue

            if status == STATUS_COMPLETE:
                stats["complete_count"] += 1
            elif status == STATUS_INCOMPLETE:
                stats["incomplete_count"] += 1
            elif status == STATUS_NOT_APPLICABLE:
                stats["not_applicable_count"] += 1

            # Steps JSON parsing
            try:
                steps = json.loads(steps_raw)
            except Exception as e:
                errors.append(f"Row {row_idx} ({case_id}): invalid JSON in steps_json: {e}")
                continue

            if not isinstance(steps, list):
                errors.append(f"Row {row_idx} ({case_id}): steps_json must be a JSON array")
                continue

            # NOT_APPLICABLE contract: steps must be empty
            if status == STATUS_NOT_APPLICABLE:
                if len(steps) != 0:
                    errors.append(f"Row {row_idx} ({case_id}): NOT_APPLICABLE must have empty steps_json, got {len(steps)} steps")
                continue

            # COMPLETE contract: must have evidence-backed verification steps
            if status == STATUS_COMPLETE:
                if len(steps) == 0:
                    errors.append(f"Row {row_idx} ({case_id}): COMPLETE must not have empty steps_json")

            # Step validation
            prev_phase_rank = -1
            for s_idx, step in enumerate(steps, start=1):
                stats["total_steps"] += 1
                if not isinstance(step, dict):
                    errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: step must be a JSON object")
                    continue

                # Required fields
                req_fields = {"step_no", "phase", "system_id", "resource_id", "operation", "state", "evidence_id"}
                if set(step.keys()) != req_fields:
                    errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: invalid fields {set(step.keys())}")

                # Consecutive numbering
                step_no = step.get("step_no")
                if step_no != s_idx:
                    errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: step_no must be {s_idx}, got {step_no}")

                phase = step.get("phase", "")
                op = step.get("operation", "")
                st = step.get("state", "")
                ev_id = step.get("evidence_id", "")

                if phase not in VALID_PHASES:
                    errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: invalid phase '{phase}'")

                if op not in ALL_VALID_OPERATIONS:
                    errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: invalid operation '{op}'")

                if st not in VALID_STATES:
                    errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: invalid state '{st}'")

                # Phase ordering: FINDING <= REMEDIATION <= VERIFICATION
                curr_rank = PHASE_RANK.get(phase, 99)
                if curr_rank < prev_phase_rank:
                    errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: phase '{phase}' out of order after rank {prev_phase_rank}")
                prev_phase_rank = curr_rank

                if phase == "FINDING":
                    stats["finding_steps"] += 1
                    if op not in VALID_FINDING_OPERATIONS:
                        errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: FINDING cannot use op '{op}'")
                    if not ev_id:
                        errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: FINDING must have non-empty evidence_id")
                elif phase == "REMEDIATION":
                    stats["remediation_steps"] += 1
                    if op not in VALID_REMEDIATION_OPERATIONS:
                        errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: REMEDIATION cannot use op '{op}'")
                    if ev_id != "":
                        errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: Proposed REMEDIATION must use empty evidence_id, got '{ev_id}'")
                elif phase == "VERIFICATION":
                    stats["verification_steps"] += 1
                    if op not in VALID_VERIFICATION_OPERATIONS:
                        errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: VERIFICATION cannot use op '{op}'")
                    if status == STATUS_COMPLETE:
                        if not ev_id:
                            errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: COMPLETE verification must cite valid evidence_id")
                    elif status == STATUS_INCOMPLETE:
                        if ev_id != "":
                            errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: Post-remediation verification must use empty evidence_id, got '{ev_id}'")

                # Evidence temporal admissibility check
                if ev_id:
                    stats["unique_evidence_cited"].add(ev_id)
                    if ev_id not in manifest:
                        errors.append(f"Row {row_idx} ({case_id}) Step {s_idx}: cited evidence_id '{ev_id}' not in manifest")
                    else:
                        ev_file = manifest[ev_id]
                        if not ev_file.is_admissible_for_case(audit_at):
                            errors.append(
                                f"Row {row_idx} ({case_id}) Step {s_idx}: cited evidence '{ev_id}' captured at "
                                f"{ev_file.captured_at.isoformat()} is after case audit_at {audit_at.isoformat()}"
                            )

    # Check case completeness
    missing_cases = set(requests.keys()) - seen_cases
    if missing_cases:
        errors.append(f"Missing {len(missing_cases)} required cases, including: {sorted(list(missing_cases))[:5]}")

    is_valid = (len(errors) == 0)
    return is_valid, errors, stats


def evaluate_public_samples() -> Dict[str, Any]:
    """Runs the audit pipeline on public sample cases and compares to sample_output.csv."""
    planner = AuditPlanner(requests_path=SAMPLE_DELETION_REQUESTS_PATH)
    sample_requests = load_deletion_requests(SAMPLE_DELETION_REQUESTS_PATH)
    results = {r.case_id: r for r in planner.audit_all(sample_requests)}

    ground_truth = {}
    with open(SAMPLE_OUTPUT_PATH, "r", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            ground_truth[r["case_id"]] = {
                "status": r["deletion_status"],
                "steps": json.loads(r["steps_json"]),
            }

    status_matches = 0
    total_cases = len(sample_requests)
    mismatches = []

    status_breakdown = {
        "COMPLETE": {"tp": 0, "expected": 0, "predicted": 0},
        "INCOMPLETE": {"tp": 0, "expected": 0, "predicted": 0},
        "NOT_APPLICABLE": {"tp": 0, "expected": 0, "predicted": 0},
    }

    step_counts_match = 0
    exact_sequence_matches = 0

    for cid, req in sorted(results.items()):
        gt = ground_truth.get(cid)
        if not gt:
            continue

        gt_status = gt["status"]
        pred_status = req.deletion_status

        status_breakdown[gt_status]["expected"] += 1
        status_breakdown[pred_status]["predicted"] += 1

        if pred_status == gt_status:
            status_matches += 1
            status_breakdown[gt_status]["tp"] += 1
        else:
            mismatches.append({
                "case_id": cid,
                "expected": gt_status,
                "predicted": pred_status,
                "notes": req.notes,
            })

        pred_steps = [s.to_dict() for s in req.steps]
        gt_steps = gt["steps"]

        if len(pred_steps) == len(gt_steps):
            step_counts_match += 1

        # Check exact sequence match (ignoring step_no which is consecutive)
        seq_match = True
        if len(pred_steps) != len(gt_steps):
            seq_match = False
        else:
            for ps, gs in zip(pred_steps, gt_steps):
                for k in ["phase", "system_id", "resource_id", "operation", "state", "evidence_id"]:
                    if ps.get(k) != gs.get(k):
                        seq_match = False
                        break
                if not seq_match:
                    break

        if seq_match:
            exact_sequence_matches += 1

    return {
        "total_cases": total_cases,
        "status_matches": status_matches,
        "status_accuracy": status_matches / total_cases if total_cases else 0.0,
        "step_counts_match": step_counts_match,
        "exact_sequence_matches": exact_sequence_matches,
        "sequence_accuracy": exact_sequence_matches / total_cases if total_cases else 0.0,
        "status_breakdown": status_breakdown,
        "mismatches": mismatches,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Ghost Data Audit Agent - Evaluation Pipeline")
    parser.add_argument("--output", type=Path, default=OUTPUT_PATH, help="Path to output.csv")
    parser.add_argument("--requests", type=Path, default=DELETION_REQUESTS_PATH, help="Path to deletion_requests.csv")
    args = parser.parse_args()

    print("=" * 70)
    print("1. EVALUATING PUBLIC SAMPLES (sample_deletion_requests.csv)")
    print("=" * 70)
    sample_eval = evaluate_public_samples()
    print(f"Sample Cases:         {sample_eval['total_cases']}")
    print(f"Status Accuracy:      {sample_eval['status_matches']}/{sample_eval['total_cases']} ({sample_eval['status_accuracy']*100:.2f}%)")
    print(f"Sequence Accuracy:    {sample_eval['exact_sequence_matches']}/{sample_eval['total_cases']} ({sample_eval['sequence_accuracy']*100:.2f}%)")
    print("\nStatus Breakdown:")
    for st, counts in sample_eval["status_breakdown"].items():
        rec = counts["tp"] / counts["expected"] if counts["expected"] else 0.0
        prec = counts["tp"] / counts["predicted"] if counts["predicted"] else 0.0
        print(f"  {st:15s} TP={counts['tp']:2d}/{counts['expected']:2d} (Recall: {rec*100:5.1f}%, Prec: {prec*100:5.1f}%)")

    if sample_eval["mismatches"]:
        print("\nMismatched Sample Cases:")
        for m in sample_eval["mismatches"]:
            print(f"  {m['case_id']}: Expected={m['expected']} vs Predicted={m['predicted']}")

    print("\n" + "=" * 70)
    print(f"2. VALIDATING FULL OUTPUT FILE ({args.output})")
    print("=" * 70)
    is_valid, errors, stats = validate_output_csv(args.output, args.requests)

    print(f"Total Rows:           {stats['total_rows']}")
    print(f"  COMPLETE:           {stats['complete_count']}")
    print(f"  INCOMPLETE:         {stats['incomplete_count']}")
    print(f"  NOT_APPLICABLE:     {stats['not_applicable_count']}")
    print(f"Total Steps:          {stats['total_steps']}")
    print(f"  FINDING steps:      {stats['finding_steps']}")
    print(f"  REMEDIATION steps:  {stats['remediation_steps']}")
    print(f"  VERIFICATION steps: {stats['verification_steps']}")
    print(f"Unique Evidence Files Cited: {len(stats['unique_evidence_cited'])}")

    if not is_valid:
        print(f"\nVALIDATION FAILED WITH {len(errors)} ERRORS:")
        for e in errors[:20]:
            print(f"  - {e}")
        if len(errors) > 20:
            print(f"  ... and {len(errors) - 20} more errors.")
        return 1
    else:
        print("\nALL CONTRACT VALIDATIONS PASSED: output.csv is 100% compliant!")
        return 0


if __name__ == "__main__":
    sys.exit(main())
