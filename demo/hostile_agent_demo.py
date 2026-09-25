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

import os
import subprocess
import sys


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


def _run(label: str, path: str) -> int:
    print(f"\\n=== {label.upper()} ===")
    print(f"pytest -q -rs {path}")
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-rs", path],
        check=False,
    )
    status = "PASS" if result.returncode == 0 else "FAIL"
    print(f"[{status}] {label}")
    return result.returncode


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

    failures = 0
    for label, path in TESTS:
        failures += _run(label, path)

    print("\\n=== ATTACK MATRIX ===")
    print("controller SIGTERM/SIGKILL      -> denied")
    print("controller ptrace/memory       -> denied")
    print("controller IPC/socket tamper   -> denied")
    print("cross-boundary cgroup migrate -> denied")
    print("cgroup workload containment    -> enforced")
    print("post-containment egress        -> denied")
    print("stale execution lease          -> invalidated")
    print("")

    if failures:
        print("DEMO RESULT: FAILED")
        print("A boundary did not reproduce the expected proof.")
        return 1

    print("DEMO RESULT: CONTAINED")
    print("DEMO RESULT: ADVERSARIAL PROOFS PASSED")
    print(
        "Proof receipts and recovery evidence are covered by the regression "
        "suite; this demo does not claim cryptographic attestation of the host."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
