import pytest

from agent_containment.control import ContainmentService
from agent_containment.containment import ContainmentController
from agent_containment.egress_enforcement import LinuxEbpfExternalEnforcer
from agent_containment.incident_state import IncidentRegistry, IncidentState
from agent_containment.runtime import Runtime, RuntimeState
from agent_containment.runtime_fence import RuntimeFenceRegistry


def _ebpf_controller(tmp_path):
    tmp_path.mkdir(parents=True, exist_ok=True)
    cgroup = tmp_path / "agent"
    cgroup.mkdir()
    controller = tmp_path / "ctl"
    controller.write_text("")
    obj = tmp_path / "policy.o"
    obj.write_text("")
    pin_dir = tmp_path / "pin"
    pin_dir.mkdir()
    (pin_dir / "egress_link").write_text("pinned")
    return LinuxEbpfExternalEnforcer(controller, obj, cgroup, pin_dir), pin_dir


def test_restart_reconciles_external_containment_before_recovery(monkeypatch, tmp_path):
    incident_path = tmp_path / "incidents.json"
    first_enforcer, pin_dir = _ebpf_controller(tmp_path)
    calls = []

    class Result:
        returncode = 0
        stderr = ""
        stdout = ""

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if len(cmd) > 1 and cmd[1] == "detach":
            pin_dir.joinpath("egress_link").unlink(missing_ok=True)
        return Result()

    monkeypatch.setattr(
        "agent_containment.egress_enforcement.subprocess.run", fake_run
    )

    first = ContainmentService(incidents=IncidentRegistry(incident_path))
    first.register(
        "agent-restart-proof",
        containment=ContainmentController(
            Runtime("agent-restart-proof"), enforcers=[first_enforcer]
        ),
    )
    report = first.contain("agent-restart-proof")
    assert report.epoch == 1
    assert report.external_verified
    assert pin_dir.joinpath("egress_link").exists()

    # Recreate the surviving external-enforcement artifact after the first
    # controller's test fixture has established containment. A fresh
    # controller instance must reconcile that existing boundary.
    pin_dir.joinpath("egress_link").write_text("pinned")
    second_enforcer = LinuxEbpfExternalEnforcer(
        tmp_path / "ctl", tmp_path / "policy.o", tmp_path / "agent", pin_dir
    )
    second = ContainmentService(incidents=IncidentRegistry(incident_path))
    restarted_runtime = Runtime("agent-restart-proof")
    restarted_runtime.restore_contained(1)
    runtime = second.register(
        "agent-restart-proof",
        containment=ContainmentController(
            restarted_runtime, enforcers=[second_enforcer]
        ),
    )

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1
    before = len(calls)
    auth = second.issue_recovery_authorization("agent-restart-proof")
    assert len(calls) > before
    assert calls[-1][1] == "verify"
    assert runtime.epoch == 1
    assert runtime.state is RuntimeState.CONTAINED

    assert second.recover("agent-restart-proof", auth) == 2
    assert runtime.state is RuntimeState.ACTIVE


def test_restart_blocks_recovery_when_external_containment_cannot_reconcile(
    monkeypatch, tmp_path
):
    incident_path = tmp_path / "incidents.json"
    first_enforcer, pin_dir = _ebpf_controller(tmp_path / "shared")
    second_enforcer = LinuxEbpfExternalEnforcer(
        tmp_path / "shared" / "ctl",
        tmp_path / "shared" / "policy.o",
        tmp_path / "shared" / "agent",
        pin_dir,
    )

    class Result:
        returncode = 0
        stderr = ""
        stdout = ""

    def fake_run(cmd, **kwargs):
        return Result()

    monkeypatch.setattr(
        "agent_containment.egress_enforcement.subprocess.run", fake_run
    )

    first = ContainmentService(incidents=IncidentRegistry(incident_path))
    first.register(
        "agent-restart-block",
        containment=ContainmentController(
            Runtime("agent-restart-block"), enforcers=[first_enforcer]
        ),
    )
    assert first.contain("agent-restart-block").complete

    def fail_restart_verify(cmd, **kwargs):
        if len(cmd) > 1 and cmd[1] == "verify" and str(second_enforcer._pin_dir) in cmd:
            return type(
                "Result",
                (),
                {
                    "returncode": 1,
                    "stderr": "wrong target",
                    "stdout": "",
                },
            )()
        return Result()

    monkeypatch.setattr(
        "agent_containment.egress_enforcement.subprocess.run", fail_restart_verify
    )

    second = ContainmentService(incidents=IncidentRegistry(incident_path))
    restarted_runtime = Runtime("agent-restart-block")
    restarted_runtime.restore_contained(1)
    runtime = second.register(
        "agent-restart-block",
        containment=ContainmentController(
            restarted_runtime, enforcers=[second_enforcer]
        ),
    )

    with pytest.raises(RuntimeError, match="reconciliation failed"):
        second.issue_recovery_authorization("agent-restart-block")

    assert runtime.state is RuntimeState.CONTAINED
    assert runtime.epoch == 1
    incident = second.incident("agent-restart-block")
    assert incident is not None
    assert incident.state is IncidentState.CONTAINED


def test_restart_repairs_missing_fence_after_interrupted_recovery(monkeypatch, tmp_path):
    incident_path = tmp_path / "incidents.json"
    fence_path = tmp_path / "fences.json"
    agent_id = "agent-recovery-interrupted"

    incidents = IncidentRegistry(incident_path)
    fences = RuntimeFenceRegistry(fence_path)
    first = ContainmentService(incidents=incidents, fences=fences)
    first_runtime = Runtime(agent_id)
    first.register(
        agent_id,
        containment=ContainmentController(first_runtime),
    )
    old_lease = first_runtime.acquire_lease()
    assert old_lease is not None

    assert first.contain(agent_id).epoch == 1
    assert not first_runtime.lease_valid(old_lease)
    authorization = first.issue_recovery_authorization(agent_id)

    def crash_before_recovered_record(_incident_id):
        raise RuntimeError("simulated controller crash before recovered record")

    monkeypatch.setattr(first.incidents, "mark_recovered", crash_before_recovered_record)
    with pytest.raises(RuntimeError, match="simulated controller crash"):
        first.recover(agent_id, authorization)

    # The fence has been cleared, but the durable incident still says contained.
    assert first.fences.get(agent_id) is None
    assert first.incidents.latest_for_agent(agent_id).state is IncidentState.CONTAINED
    assert first_runtime.state is RuntimeState.CONTAINED

    # Rebuild all controller-owned state from disk, as a fresh process would.
    restarted_incidents = IncidentRegistry(incident_path)
    restarted_fences = RuntimeFenceRegistry(fence_path)
    restarted = ContainmentService(
        incidents=restarted_incidents,
        fences=restarted_fences,
    )
    restarted_runtime = Runtime(agent_id)
    restarted_runtime.restore_contained(1)
    restarted.register(
        agent_id,
        containment=ContainmentController(restarted_runtime),
    )

    # Restart repairs the missing fence from the still-contained incident;
    # it does not activate the runtime or accept the pre-containment lease.
    fence = restarted_fences.get(agent_id)
    assert fence is not None
    assert fence.containment_epoch == 1
    assert restarted_runtime.state is RuntimeState.CONTAINED
    assert not restarted_runtime.lease_valid(old_lease)

    resumed_authorization = restarted.issue_recovery_authorization(agent_id)
    assert restarted_runtime.state is RuntimeState.CONTAINED
    assert restarted.recover(agent_id, resumed_authorization) == 2
    assert restarted_runtime.state is RuntimeState.ACTIVE
    assert restarted_runtime.epoch == 2
    assert not restarted_runtime.lease_valid(old_lease)



def test_restart_recontains_after_interrupted_recovery_released_enforcers(
    monkeypatch, tmp_path
):
    from agent_containment.enforcer import EnforcementResult, EnforcementStatus

    incident_path = tmp_path / "incidents.json"
    fence_path = tmp_path / "fences.json"
    agent_id = "agent-recovery-released"
    external_state = {"contained": False}

    class StatefulEnforcer:
        name = "stateful-test-enforcer"

        def contain(self, _agent_id):
            external_state["contained"] = True
            return EnforcementResult(self.name, EnforcementStatus.ENFORCED)

        def verify_contained(self, _agent_id):
            status = (
                EnforcementStatus.ENFORCED
                if external_state["contained"]
                else EnforcementStatus.VERIFICATION_FAILED
            )
            return EnforcementResult(self.name, status)

        def release(self, _agent_id):
            external_state["contained"] = False
            return EnforcementResult(self.name, EnforcementStatus.RELEASED)

        def verify_released(self, _agent_id):
            status = (
                EnforcementStatus.RELEASED
                if not external_state["contained"]
                else EnforcementStatus.VERIFICATION_FAILED
            )
            return EnforcementResult(self.name, status)

    first = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=RuntimeFenceRegistry(fence_path),
    )
    first_runtime = Runtime(agent_id)
    first.register(
        agent_id,
        containment=ContainmentController(
            first_runtime, enforcers=[StatefulEnforcer()]
        ),
    )
    old_lease = first_runtime.acquire_lease()
    assert old_lease is not None
    assert first.contain(agent_id).certified
    authorization = first.issue_recovery_authorization(agent_id)

    def crash_after_enforcer_release(_incident_id):
        assert external_state["contained"] is False
        raise RuntimeError("simulated controller crash after enforcer release")

    monkeypatch.setattr(
        first.incidents, "mark_recovered", crash_after_enforcer_release
    )
    with pytest.raises(RuntimeError, match="after enforcer release"):
        first.recover(agent_id, authorization)

    assert first.fences.get(agent_id) is None
    assert first.incidents.latest_for_agent(agent_id).state is IncidentState.CONTAINED
    assert first_runtime.state is RuntimeState.CONTAINED
    assert external_state["contained"] is False
    assert not first_runtime.lease_valid(old_lease)

    restarted = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=RuntimeFenceRegistry(fence_path),
    )
    restarted_runtime = Runtime(agent_id)
    restarted_runtime.restore_contained(1)
    restarted.register(
        agent_id,
        containment=ContainmentController(
            restarted_runtime, enforcers=[StatefulEnforcer()]
        ),
    )

    repaired_fence = restarted.fences.get(agent_id)
    assert repaired_fence is not None
    assert repaired_fence.containment_epoch == 1
    assert restarted_runtime.state is RuntimeState.CONTAINED
    assert external_state["contained"] is False

    # Recovery authorization must re-establish and verify external containment.
    resumed_authorization = restarted.issue_recovery_authorization(agent_id)
    assert external_state["contained"] is True
    assert restarted_runtime.state is RuntimeState.CONTAINED
    assert not restarted_runtime.lease_valid(old_lease)

    assert restarted.recover(agent_id, resumed_authorization) == 2
    assert external_state["contained"] is False
    assert restarted_runtime.state is RuntimeState.ACTIVE
    assert restarted_runtime.epoch == 2
    assert not restarted_runtime.lease_valid(old_lease)

