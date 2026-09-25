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
    (
        "controller isolation",
        "tests/integration/test_controller_isolation.py",
    ),
    (
        "cgroup delegation boundary",
        "tests/integration/test_cgroup_delegation.py",
    ),
    (
        "kernel egress + process containment",
        "tests/integration/test_linux_ebpf.py",
    ),
    (
        "stale execution lease fencing",
        "tests/test_epoch_fencing_adversarial.py",
    ),
]


def _run(label: str, path: str, evidence: list[dict[str, object]]) -> int:
    print(f"\n=== {label.upper()} ===")
    print(f"pytest -q -rs {path}")
    started = time.monotonic()
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-rs", path],
        check=False,
    )
    duration = time.monotonic() - started
    status = "PASS" if result.returncode == 0 else "FAIL"
    print(f"[{status}] {label}")
    evidence.append(
        {
            "name": label,
            "test_path": path,
            "result": "passed" if result.returncode == 0 else "failed",
            "exit_code": result.returncode,
            "duration_seconds": round(duration, 6),
        }
    )
    return result.returncode


def _write_evidence(evidence: list[dict[str, object]], result: str | None = None) -> None:
    if not evidence:
        raise ValueError("cannot produce hostile-agent evidence without recorded tests")
    derived_result = "contained" if all(
        item.get("result") == "passed" and item.get("exit_code") == 0 for item in evidence
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
        "attack_matrix": [
            {"attack": "controller_signal", "expected": "denied"},
            {"attack": "controller_ptrace_memory", "expected": "denied"},
            {"attack": "controller_ipc_tamper", "expected": "denied"},
            {"attack": "cross_boundary_cgroup_migrate", "expected": "denied"},
            {"attack": "cgroup_workload_containment", "expected": "enforced"},
            {"attack": "post_containment_egress", "expected": "denied"},
            {"attack": "stale_execution_lease", "expected": "invalidated"},
        ],
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
    for label, path in TESTS:
        failures += _run(label, path, evidence)

    print("\n=== ATTACK MATRIX ===")
    print("controller SIGTERM/SIGKILL      -> denied")
    print("controller ptrace/memory       -> denied")
    print("controller IPC/socket tamper   -> denied")
    print("cross-boundary cgroup migrate -> denied")
    print("cgroup workload containment    -> enforced")
    print("post-containment egress        -> denied")
    print("stale execution lease          -> invalidated")
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
