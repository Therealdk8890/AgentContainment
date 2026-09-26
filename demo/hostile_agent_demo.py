"""Run the real hostile-agent containment demonstration.

This is the integration-facing showcase for AgentContainment. It runs the
existing Linux adversarial proofs rather than simulating hostile behavior.

Requirements:
    Linux, root, cgroup v2, and AGENT_CONTAINMENT_RUN_PRIVILEGED_TESTS=1.
    The eBPF test additionally requires the build artifacts from
    scripts/build_ebpf.sh.

No test intentionally attacks anything outside its temporary test resources.
"""

from __future__ import annotations

import json
import os
import platform
import subprocess
import sys
import time
from datetime import datetime, timezone


TESTS = [
    {
        "name": "controller isolation",
        "path": "tests/integration/test_controller_isolation.py::test_unprivileged_agent_cannot_interfere_with_controller",
        "attacks": ("controller_signal", "controller_ptrace_memory", "controller_ipc_tamper"),
        "proof_ids": ("controller_signal", "controller_ptrace_memory", "controller_ipc_tamper"),
    },
    {
        "name": "cgroup delegation boundary",
        "path": "tests/integration/test_cgroup_delegation.py::test_non_root_process_uses_delegated_cgroup_subtree",
        "attacks": ("cross_boundary_cgroup_migrate",),
        "proof_ids": ("cross_boundary_cgroup_migrate",),
    },
    {
        "name": "process containment",
        "path": "tests/integration/test_linux_ebpf.py::test_controller_containment_kills_hostile_cgroup_process",
        "attacks": ("cgroup_workload_containment",),
        "proof_ids": ("cgroup_workload_containment",),
    },
    {
        "name": "kernel egress containment",
        "path": "tests/integration/test_linux_ebpf.py::test_linux_ebpf_blocks_subprocess_egress_after_containment",
        "attacks": ("post_containment_egress",),
        "proof_ids": ("post_containment_egress",),
    },
    {
        "name": "stale execution lease fencing",
        "path": "tests/test_epoch_fencing_adversarial.py::test_stale_execution_lease_cannot_cross_containment_or_recovery",
        "attacks": ("stale_execution_lease",),
        "proof_ids": ("stale_execution_lease",),
    },
]

ATTACK_MATRIX = (
    {
        "attack": "controller_signal",
        "expected": "denied",
        "test_path": "tests/integration/test_controller_isolation.py::test_unprivileged_agent_cannot_interfere_with_controller",
    },
    {
        "attack": "controller_ptrace_memory",
        "expected": "denied",
        "test_path": "tests/integration/test_controller_isolation.py::test_unprivileged_agent_cannot_interfere_with_controller",
    },
    {
        "attack": "controller_ipc_tamper",
        "expected": "denied",
        "test_path": "tests/integration/test_controller_isolation.py::test_unprivileged_agent_cannot_interfere_with_controller",
    },
    {
        "attack": "cross_boundary_cgroup_migrate",
        "expected": "denied",
        "test_path": "tests/integration/test_cgroup_delegation.py::test_non_root_process_uses_delegated_cgroup_subtree",
    },
    {
        "attack": "cgroup_workload_containment",
        "expected": "enforced",
        "test_path": "tests/integration/test_linux_ebpf.py::test_controller_containment_kills_hostile_cgroup_process",
    },
    {
        "attack": "post_containment_egress",
        "expected": "denied",
        "test_path": "tests/integration/test_linux_ebpf.py::test_linux_ebpf_blocks_subprocess_egress_after_containment",
    },
    {
        "attack": "stale_execution_lease",
        "expected": "invalidated",
        "test_path": "tests/test_epoch_fencing_adversarial.py::test_stale_execution_lease_cannot_cross_containment_or_recovery",
    },
)


def _run(test: dict[str, object], evidence: list[dict[str, object]]) -> int:
    label = str(test["name"])
    path = str(test["path"])
    print(f"\n=== {label.upper()} ===")
    print(f"pytest -q -rs {path}")
    started = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-rs", "-s", path],
        capture_output=True,
        text=True,
        check=False,
    )
    output = result.stdout + result.stderr
    proof_ids = [proof_id for proof_id in test["proof_ids"] if f"AC_PROOF:{proof_id}" in output]
    missing_proofs = [proof_id for proof_id in test["proof_ids"] if proof_id not in proof_ids]
    duration = time.monotonic() - started
    status = "PASS" if result.returncode == 0 and not missing_proofs else "FAIL"
    if missing_proofs:
        print(f"[FAIL] {label}: missing proof markers {missing_proofs}")
    else:
        print(f"[{status}] {label}")
    evidence.append(
        {
            "name": label,
            "test_path": path,
            "test_nodeid": path,
            "attacks_covered": list(test["attacks"]),
            "proof_ids": proof_ids,
            "result": "passed" if result.returncode == 0 and not missing_proofs else "failed",
            "exit_code": result.returncode,
            "duration_seconds": round(duration, 6),
        }
    )
    return result.returncode


def _write_evidence(evidence: list[dict[str, object]], result: str | None = None) -> None:
    if not evidence:
        raise ValueError("cannot produce hostile-agent evidence without recorded tests")
    evidence_by_path = {item.get("test_path"): item for item in evidence}
    if len(evidence_by_path) != len(evidence):
        raise ValueError("hostile-agent evidence contains duplicate test paths")

    expected_attacks = {item["attack"] for item in ATTACK_MATRIX}
    covered_attacks = {
        attack
        for item in evidence
        for attack in item.get("attacks_covered", [])
    }
    if covered_attacks != expected_attacks:
        missing = sorted(expected_attacks - covered_attacks)
        unexpected = sorted(covered_attacks - expected_attacks)
        raise ValueError(
            f"hostile-agent attack coverage mismatch; missing={missing}, unexpected={unexpected}"
        )

    expected_nodeids = {str(item["path"]) for item in TESTS}
    recorded_nodeids = {str(item.get("test_nodeid")) for item in evidence}
    if recorded_nodeids != expected_nodeids:
        raise ValueError(
            f"hostile-agent proof nodeid mismatch; missing={sorted(expected_nodeids - recorded_nodeids)}, "
            f"unexpected={sorted(recorded_nodeids - expected_nodeids)}"
        )

    for matrix_item in ATTACK_MATRIX:
        test = evidence_by_path.get(matrix_item["test_path"])
        if test is None:
            raise ValueError(
                f"attack {matrix_item['attack']!r} has no recorded test evidence"
            )
        if test.get("test_nodeid") != matrix_item["test_path"]:
            raise ValueError(
                f"attack {matrix_item['attack']!r} is not bound to its executed pytest nodeid"
            )
        if matrix_item["attack"] not in test.get("attacks_covered", []):
            raise ValueError(
                f"attack {matrix_item['attack']!r} is not covered by "
                f"{matrix_item['test_path']!r}"
            )
        if matrix_item["attack"] not in test.get("proof_ids", []):
            raise ValueError(
                f"attack {matrix_item['attack']!r} has no executed proof marker"
            )

    expected_proofs = {proof_id for item in TESTS for proof_id in item["proof_ids"]}
    recorded_proofs = {proof_id for item in evidence for proof_id in item.get("proof_ids", [])}
    if recorded_proofs != expected_proofs:
        raise ValueError(
            f"hostile-agent proof marker mismatch; missing={sorted(expected_proofs - recorded_proofs)}, "
            f"unexpected={sorted(recorded_proofs - expected_proofs)}"
        )

    derived_result = "contained" if all(
        item.get("result") == "passed" and item.get("exit_code") == 0
        for item in evidence
    ) else "failed"
    if result is not None and result != derived_result:
        raise ValueError(
            f"evidence result {result!r} is inconsistent with recorded test outcomes; "
            f"expected {derived_result!r}"
        )

    payload = {
        "schema_version": 1,
        "evidence_type": "hostile_agent_demo",
        "result": derived_result,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repository": os.environ.get("GITHUB_REPOSITORY"),
        "commit_sha": os.environ.get("GITHUB_SHA"),
        "run_id": os.environ.get("GITHUB_RUN_ID"),
        "runner": {
            "os": sys.platform,
            "platform": platform.platform(),
            "kernel": platform.release(),
            "euid": os.geteuid(),
        },
        "tests": evidence,
        "attack_matrix": list(ATTACK_MATRIX),
        "proof_markers": sorted(recorded_proofs),
        "claims": {
            "scope": "test evidence from temporary resources on the tested Linux host",
            "universal_security_guarantee": False,
            "host_cryptographic_attestation": False,
        },
    }
    with open("hostile-agent-evidence.json", "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True)
        handle.write("\n")


def main() -> int:
    if sys.platform != "linux":
        print("HOSTILE-AGENT DEMO: Linux is required.", file=sys.stderr)
        return 2
    if os.geteuid() != 0:
        print("HOSTILE-AGENT DEMO: run as root.", file=sys.stderr)
        return 2
    if os.environ.get("AGENT_CONTAINMENT_RUN_PRIVILEGED_TESTS") != "1":
        print(
            "HOSTILE-AGENT DEMO: set AGENT_CONTAINMENT_RUN_PRIVILEGED_TESTS=1.",
            file=sys.stderr,
        )
        return 2

    print("AGENTCONTAINMENT HOSTILE-AGENT DEMO")
    print("=" * 40)
    print("The agent is treated as hostile. The controller remains trusted.")
    print("The demo uses temporary test resources and cleans them up.")

    evidence: list[dict[str, object]] = []
    failures = 0
    for test in TESTS:
        failures += _run(test, evidence)

    print("\n=== ATTACK MATRIX ===")
    for item in ATTACK_MATRIX:
        print(
            f"{item['attack']:<30} -> {item['expected']}"
        )
    print("")

    if failures:
        _write_evidence(evidence, "failed")
        print("DEMO RESULT: FAILED")
        print("A boundary did not reproduce the expected proof.")
        return 1

    _write_evidence(evidence, "contained")
    print("DEMO RESULT: CONTAINED")
    print("DEMO RESULT: ADVERSARIAL PROOFS PASSED")
    print(
        "Proof receipts and recovery evidence are covered by the regression "
        "suite; this demo does not claim cryptographic attestation of the host."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
