from __future__ import annotations

import importlib.util
import json
from pathlib import Path


DEMO_PATH = Path(__file__).resolve().parents[1] / "demo" / "hostile_agent_demo.py"
SPEC = importlib.util.spec_from_file_location("hostile_agent_demo", DEMO_PATH)
assert SPEC is not None and SPEC.loader is not None
DEMO = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DEMO)
_write_evidence = DEMO._write_evidence


REQUIRED_TOP_LEVEL_KEYS = {
    "schema_version",
    "evidence_type",
    "result",
    "generated_at",
    "repository",
    "commit_sha",
    "run_id",
    "runner",
    "tests",
    "attack_matrix",
    "claims",
    "proof_markers",
}

EXPECTED_ATTACKS = {
    "controller_signal": "denied",
    "controller_ptrace_memory": "denied",
    "controller_ipc_tamper": "denied",
    "cross_boundary_cgroup_migrate": "denied",
    "cgroup_workload_containment": "enforced",
    "post_containment_egress": "denied",
    "stale_execution_lease": "invalidated",
}


def _complete_evidence(result="passed", exit_code=0):
    tests = [
        ("controller isolation", "tests/integration/test_controller_isolation.py::test_unprivileged_agent_cannot_interfere_with_controller", ["controller_signal", "controller_ptrace_memory", "controller_ipc_tamper"]),
        ("cgroup delegation boundary", "tests/integration/test_cgroup_delegation.py::test_non_root_process_uses_delegated_cgroup_subtree", ["cross_boundary_cgroup_migrate"]),
        ("process containment", "tests/integration/test_linux_ebpf.py::test_controller_containment_kills_hostile_cgroup_process", ["cgroup_workload_containment"]),
        ("kernel egress containment", "tests/integration/test_linux_ebpf.py::test_linux_ebpf_blocks_subprocess_egress_after_containment", ["post_containment_egress"]),
        ("stale execution lease fencing", "tests/test_epoch_fencing_adversarial.py::test_stale_execution_lease_cannot_cross_containment_or_recovery", ["stale_execution_lease"]),
    ]
    return [
        {
            "name": name,
            "test_path": nodeid,
            "test_nodeid": nodeid,
            "attacks_covered": attacks,
            "proof_ids": attacks,
            "result": result,
            "exit_code": exit_code,
            "duration_seconds": 0.1,
        }
        for name, nodeid, attacks in tests
    ]

def test_hostile_agent_evidence_schema_is_stable(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    evidence = _complete_evidence()

    _write_evidence(evidence, "contained")

    payload = json.loads((tmp_path / "hostile-agent-evidence.json").read_text())
    assert set(payload) == REQUIRED_TOP_LEVEL_KEYS
    assert payload["schema_version"] == 1
    assert payload["evidence_type"] == "hostile_agent_demo"
    assert payload["result"] == "contained"

    attacks = {item["attack"]: item["expected"] for item in payload["attack_matrix"]}
    assert attacks == EXPECTED_ATTACKS
    assert payload["proof_markers"] == sorted(EXPECTED_ATTACKS)

    test_paths = {item["test_path"] for item in payload["tests"]}
    nodeids = {item["test_nodeid"] for item in payload["tests"]}
    assert nodeids == test_paths
    for item in payload["attack_matrix"]:
        assert item["test_path"] in test_paths

    assert payload["claims"]["universal_security_guarantee"] is False
    assert payload["claims"]["host_cryptographic_attestation"] is False
    assert len(payload["tests"]) == 5
    assert all(item["result"] == "passed" for item in payload["tests"])

def test_hostile_agent_evidence_rejects_incomplete_attack_coverage(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    evidence = [
        {
            "name": "controller isolation",
            "test_path": "tests/integration/test_controller_isolation.py::test_unprivileged_agent_cannot_interfere_with_controller",
            "attacks_covered": ["controller_signal"],
            "result": "passed",
            "exit_code": 0,
            "duration_seconds": 0.1,
        }
    ]

    try:
        _write_evidence(evidence, "contained")
    except ValueError as exc:
        assert "attack coverage mismatch" in str(exc)
    else:
        raise AssertionError("incomplete attack coverage was accepted")

def test_hostile_agent_evidence_rejects_inconsistent_contained_result(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    try:
        _write_evidence(_complete_evidence("failed", 1), "contained")
    except ValueError as exc:
        assert "inconsistent" in str(exc)
    else:
        raise AssertionError("inconsistent contained evidence was accepted")


def test_hostile_agent_evidence_rejects_empty_evidence(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    try:
        _write_evidence([], "contained")
    except ValueError as exc:
        assert "without recorded tests" in str(exc)
    else:
        raise AssertionError("empty evidence was accepted")




def test_hostile_agent_evidence_records_failures(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    _write_evidence(_complete_evidence("failed", 1), "failed")

    payload = json.loads((tmp_path / "hostile-agent-evidence.json").read_text())
    assert payload["result"] == "failed"
    assert payload["tests"][0]["result"] == "failed"
    assert payload["tests"][0]["exit_code"] == 1
