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


def test_hostile_agent_evidence_schema_is_stable(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    evidence = [
        {
            "name": "controller isolation",
            "test_path": "tests/integration/test_controller_isolation.py",
            "result": "passed",
            "exit_code": 0,
            "duration_seconds": 0.1,
        }
    ]

    _write_evidence(evidence, "contained")

    payload = json.loads((tmp_path / "hostile-agent-evidence.json").read_text())
    assert set(payload) == REQUIRED_TOP_LEVEL_KEYS
    assert payload["schema_version"] == 1
    assert payload["evidence_type"] == "hostile_agent_demo"
    assert payload["result"] == "contained"

    attacks = {
        item["attack"]: item["expected"] for item in payload["attack_matrix"]
    }
    assert attacks == EXPECTED_ATTACKS

    test_paths = {item["test_path"] for item in payload["tests"]}
    for item in payload["attack_matrix"]:
        assert item["test_path"] in test_paths

    assert payload["claims"]["universal_security_guarantee"] is False
    assert payload["claims"]["host_cryptographic_attestation"] is False

    assert len(payload["tests"]) == 1
    assert payload["tests"][0]["result"] == "passed"


def test_hostile_agent_evidence_rejects_inconsistent_contained_result(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)

    try:
        _write_evidence(
            [
                {
                    "name": "controller isolation",
                    "test_path": "tests/integration/test_controller_isolation.py",
                    "result": "failed",
                    "exit_code": 1,
                    "duration_seconds": 0.2,
                }
            ],
            "contained",
        )
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

    _write_evidence(
        [
            {
                "name": "controller isolation",
                "test_path": "tests/integration/test_controller_isolation.py",
                "result": "failed",
                "exit_code": 1,
                "duration_seconds": 0.2,
            }
        ],
        "failed",
    )

    payload = json.loads((tmp_path / "hostile-agent-evidence.json").read_text())
    assert payload["result"] == "failed"
    assert payload["tests"][0]["result"] == "failed"
    assert payload["tests"][0]["exit_code"] == 1
