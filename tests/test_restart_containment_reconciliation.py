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




def test_restart_aborts_recovery_committed_before_runtime_activation(
    monkeypatch, tmp_path
):
    from agent_containment.enforcer import EnforcementResult, EnforcementStatus

    incident_path = tmp_path / "incidents.json"
    fence_path = tmp_path / "fences.json"
    agent_id = "agent-recovery-commit-before-activation"
    external_state = {"contained": False}

    class StatefulEnforcer:
        name = "stateful-recovery-commit-enforcer"

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

    incidents = IncidentRegistry(incident_path)
    fences = RuntimeFenceRegistry(fence_path)
    first = ContainmentService(incidents=incidents, fences=fences)
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
    original_mark_recovered = first.incidents.mark_recovered

    def crash_after_recovered_commit(incident_id):
        original_mark_recovered(incident_id)
        raise RuntimeError("simulated crash after durable recovered commit")

    monkeypatch.setattr(
        first.incidents, "mark_recovered", crash_after_recovered_commit
    )
    with pytest.raises(RuntimeError, match="after durable recovered commit"):
        first.recover(agent_id, authorization)

    # The disk record says RECOVERED, but the runtime never activated.
    assert first.incidents.latest_for_agent(agent_id).state is IncidentState.RECOVERED
    assert first.fences.get(agent_id) is None
    assert first_runtime.state is RuntimeState.CONTAINED
    assert external_state["contained"] is False
    assert not first_runtime.lease_valid(old_lease)

    # Simulate a new process: a fresh runtime is explicitly restored to the
    # old contained epoch; a RECOVERED record must not activate it.
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

    incident = restarted.incident(agent_id)
    assert incident is not None
    assert incident.state is IncidentState.CONTAINED
    assert restarted_runtime.state is RuntimeState.CONTAINED
    assert restarted_runtime.epoch == 1
    fence = restarted.fences.get(agent_id)
    assert fence is not None
    assert fence.containment_epoch == 1
    assert external_state["contained"] is False
    assert not restarted_runtime.lease_valid(old_lease)

    with pytest.raises(PermissionError, match="stale"):
        restarted.recover(agent_id, authorization)

    # A new authorization first reconciles/re-establishes external containment.
    resumed_authorization = restarted.issue_recovery_authorization(agent_id)
    assert external_state["contained"] is True
    assert restarted_runtime.state is RuntimeState.CONTAINED
    assert restarted.recover(agent_id, resumed_authorization) == 2
    assert restarted_runtime.state is RuntimeState.ACTIVE
    assert restarted_runtime.epoch == 2
    assert external_state["contained"] is False
    assert not restarted_runtime.lease_valid(old_lease)



def test_restart_accepts_runtime_activated_before_controller_crash(
    monkeypatch, tmp_path
):
    from agent_containment.enforcer import EnforcementResult, EnforcementStatus

    incident_path = tmp_path / "incidents-activated.json"
    fence_path = tmp_path / "fences-activated.json"
    agent_id = "agent-runtime-activated-before-controller-crash"
    external_state = {"contained": False}

    class StatefulEnforcer:
        name = "activated-before-crash-enforcer"

        def contain(self, _agent_id):
            external_state["contained"] = True
            return EnforcementResult(self.name, EnforcementStatus.ENFORCED)

        def verify_contained(self, _agent_id):
            status = EnforcementStatus.ENFORCED if external_state["contained"] else EnforcementStatus.VERIFICATION_FAILED
            return EnforcementResult(self.name, status)

        def release(self, _agent_id):
            external_state["contained"] = False
            return EnforcementResult(self.name, EnforcementStatus.RELEASED)

        def verify_released(self, _agent_id):
            status = EnforcementStatus.RELEASED if not external_state["contained"] else EnforcementStatus.VERIFICATION_FAILED
            return EnforcementResult(self.name, status)

    incidents = IncidentRegistry(incident_path)
    fences = RuntimeFenceRegistry(fence_path)
    first = ContainmentService(incidents=incidents, fences=fences)
    first_runtime = Runtime(agent_id)
    enforcer = StatefulEnforcer()
    first.register(
        agent_id,
        containment=ContainmentController(first_runtime, enforcers=[enforcer]),
    )
    old_lease = first_runtime.acquire_lease()
    assert old_lease is not None
    assert first.contain(agent_id).certified
    authorization = first.issue_recovery_authorization(agent_id)

    original_recover = first_runtime.recover

    def crash_after_activation(capability, expected_epoch):
        epoch = original_recover(capability, expected_epoch)
        raise SystemExit("simulated controller crash after runtime activation")

    monkeypatch.setattr(first_runtime, "recover", crash_after_activation)
    with pytest.raises(SystemExit, match="after runtime activation"):
        first.recover(agent_id, authorization)

    assert first.incidents.latest_for_agent(agent_id).state is IncidentState.RECOVERED
    assert first.incidents.latest_for_agent(agent_id).recovery_epoch == 2
    assert first.fences.get(agent_id) is None
    assert first_runtime.state is RuntimeState.ACTIVE
    assert first_runtime.epoch == 2
    assert external_state["contained"] is False
    assert not first_runtime.lease_valid(old_lease)

    restarted = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=RuntimeFenceRegistry(fence_path),
    )
    restarted_runtime = Runtime(agent_id)
    restarted_runtime._restore_active(2)
    restarted.register(
        agent_id,
        containment=ContainmentController(
            restarted_runtime, enforcers=[StatefulEnforcer()]
        ),
    )
    assert restarted_runtime.state is RuntimeState.ACTIVE
    assert restarted_runtime.epoch == 2
    assert external_state["contained"] is False
    assert not restarted_runtime.lease_valid(old_lease)
    new_lease = restarted_runtime.acquire_lease()
    assert new_lease is not None
    assert restarted_runtime.lease_valid(new_lease)



def test_restart_after_incident_record_before_containment_report_returns(
    monkeypatch, tmp_path
):
    from agent_containment.enforcer import EnforcementResult, EnforcementStatus

    incident_path = tmp_path / "incidents-report-crash.json"
    fence_path = tmp_path / "fences-report-crash.json"
    agent_id = "agent-incident-record-before-report"
    external_state = {"contained": False}

    class StatefulEnforcer:
        name = "report-crash-enforcer"

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

    incidents = IncidentRegistry(incident_path)
    fences = RuntimeFenceRegistry(fence_path)
    first = ContainmentService(incidents=incidents, fences=fences)
    first_runtime = Runtime(agent_id)
    first_enforcer = StatefulEnforcer()
    first.register(
        agent_id,
        containment=ContainmentController(
            first_runtime, enforcers=[first_enforcer]
        ),
    )
    old_lease = first_runtime.acquire_lease()
    assert old_lease is not None

    original_record_containment = incidents.record_containment

    def crash_after_durable_incident(*args, **kwargs):
        original_record_containment(*args, **kwargs)
        raise SystemExit("simulated process crash after incident persistence")

    monkeypatch.setattr(incidents, "record_containment", crash_after_durable_incident)
    with pytest.raises(SystemExit, match="after incident persistence"):
        first.contain(agent_id)

    # The caller received no report, but both the fence and incident are durable.
    incident = IncidentRegistry(incident_path).latest_for_agent(agent_id)
    fence = RuntimeFenceRegistry(fence_path).get(agent_id)
    assert incident is not None
    assert incident.state is IncidentState.CONTAINED
    assert incident.containment_epoch == 1
    assert fence is not None
    assert fence.containment_epoch == 1
    assert first_runtime.state is RuntimeState.CONTAINED
    assert not first_runtime.lease_valid(old_lease)

    # Rebuild service and runtime from durable state. The runtime must remain
    # non-executable until a fresh, reconciled recovery is explicitly authorized.
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
        containment=ContainmentController(
            restarted_runtime, enforcers=[StatefulEnforcer()]
        ),
    )
    assert restarted_runtime.state is RuntimeState.CONTAINED
    assert restarted_runtime.epoch == 1
    assert not restarted_runtime.lease_valid(old_lease)

    authorization = restarted.issue_recovery_authorization(agent_id)
    assert external_state["contained"] is True
    assert restarted_runtime.state is RuntimeState.CONTAINED
    assert restarted.recover(agent_id, authorization) == 2
    assert restarted_runtime.state is RuntimeState.ACTIVE
    assert restarted_runtime.epoch == 2
    assert external_state["contained"] is False
    assert not restarted_runtime.lease_valid(old_lease)



def test_restart_repairs_incident_after_crash_immediately_after_fence(
    monkeypatch, tmp_path
):
    from agent_containment.enforcer import EnforcementResult, EnforcementStatus

    incident_path = tmp_path / "incidents-fence-first.json"
    fence_path = tmp_path / "fences-fence-first.json"
    agent_id = "agent-fence-persisted-before-runtime-containment"
    external_state = {"contained": False}

    class StatefulEnforcer:
        name = "fence-first-enforcer"

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

    incidents = IncidentRegistry(incident_path)
    fences = RuntimeFenceRegistry(fence_path)
    first = ContainmentService(incidents=incidents, fences=fences)
    first_runtime = Runtime(agent_id)
    enforcer = StatefulEnforcer()
    first.register(
        agent_id,
        containment=ContainmentController(first_runtime, enforcers=[enforcer]),
    )
    old_lease = first_runtime.acquire_lease()
    assert old_lease is not None

    original_prepare = fences.prepare

    def crash_after_fence(agent, epoch):
        result = original_prepare(agent, epoch)
        raise SystemExit("simulated crash after durable fence write")

    monkeypatch.setattr(fences, "prepare", crash_after_fence)
    with pytest.raises(SystemExit, match="after durable fence write"):
        first.contain(agent_id)

    assert first_runtime.state is RuntimeState.ACTIVE
    assert fences.get(agent_id).containment_epoch == 1
    assert incidents.latest_for_agent(agent_id) is None
    assert external_state["contained"] is False

    # A new process reconstructs runtime admission from the fence and repairs
    # the missing incident; it must not infer that external enforcement ran.
    restarted = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=RuntimeFenceRegistry(fence_path),
    )
    restarted_runtime = restarted.register(agent_id)
    restarted.configure_containment(
        agent_id,
        ContainmentController(
            restarted_runtime, enforcers=[StatefulEnforcer()]
        ),
    )
    incident = restarted.incident(agent_id)
    assert incident is not None
    assert incident.state is IncidentState.CONTAINED
    assert incident.containment_epoch == 1
    assert "reconstructed from durable containment fence" in (incident.reason or "")
    assert restarted_runtime.state is RuntimeState.CONTAINED
    assert restarted_runtime.epoch == 1
    assert not restarted_runtime.lease_valid(old_lease)
    assert external_state["contained"] is False

    authorization = restarted.issue_recovery_authorization(agent_id)
    assert external_state["contained"] is True
    assert restarted_runtime.state is RuntimeState.CONTAINED
    assert restarted.recover(agent_id, authorization) == 2
    assert restarted_runtime.state is RuntimeState.ACTIVE
    assert restarted_runtime.epoch == 2
    assert external_state["contained"] is False
    assert not restarted_runtime.lease_valid(old_lease)


def test_restart_repairs_fence_after_crash_immediately_after_recovery_fence_clear(
    monkeypatch, tmp_path
):
    from agent_containment.enforcer import EnforcementResult, EnforcementStatus

    incident_path = tmp_path / "incidents.json"
    fence_path = tmp_path / "fences.json"
    agent_id = "agent-crash-after-fence-clear"
    external_state = {"contained": False}

    class StatefulEnforcer:
        name = "crash-after-fence-clear-enforcer"

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

    incidents = IncidentRegistry(incident_path)
    fences = RuntimeFenceRegistry(fence_path)
    first = ContainmentService(incidents=incidents, fences=fences)
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

    original_clear = fences.clear

    def clear_then_crash(target_agent):
        original_clear(target_agent)
        raise SystemExit("simulated crash immediately after durable fence clear")

    monkeypatch.setattr(fences, "clear", clear_then_crash)
    with pytest.raises(SystemExit, match="after durable fence clear"):
        first.recover(agent_id, authorization)

    assert fences.get(agent_id) is None
    assert incidents.latest_for_agent(agent_id).state is IncidentState.CONTAINED
    assert first_runtime.state is RuntimeState.CONTAINED
    assert external_state["contained"] is True
    assert not first_runtime.lease_valid(old_lease)

    # Reconstruct controller state from disk. The contained incident repairs
    # the deleted fence; external containment must be reconciled before a new
    # recovery authorization is issued.
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
        containment=ContainmentController(
            restarted_runtime, enforcers=[StatefulEnforcer()]
        ),
    )

    repaired_fence = restarted_fences.get(agent_id)
    assert repaired_fence is not None
    assert repaired_fence.containment_epoch == 1
    assert restarted_runtime.state is RuntimeState.CONTAINED
    assert not restarted_runtime.lease_valid(old_lease)
    assert external_state["contained"] is True

    with pytest.raises(PermissionError, match="stale"):
        restarted.recover(agent_id, authorization)

    resumed_authorization = restarted.issue_recovery_authorization(agent_id)
    assert external_state["contained"] is True
    assert restarted.recover(agent_id, resumed_authorization) == 2
    assert restarted_runtime.state is RuntimeState.ACTIVE
    assert restarted_runtime.epoch == 2
    assert external_state["contained"] is False
    assert not restarted_runtime.lease_valid(old_lease)



def test_restart_repairs_incident_after_crash_after_runtime_containment_before_incident_write(
    tmp_path,
):
    from agent_containment.enforcer import EnforcementResult, EnforcementStatus

    incident_path = tmp_path / "incidents-runtime-first.json"
    fence_path = tmp_path / "fences-runtime-first.json"
    agent_id = "agent-runtime-contained-before-incident"
    external_state = {"contained": False}

    class StatefulEnforcer:
        name = "runtime-first-enforcer"

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

    incidents = IncidentRegistry(incident_path)
    fences = RuntimeFenceRegistry(fence_path)
    first = ContainmentService(incidents=incidents, fences=fences)
    first_runtime = Runtime(agent_id)
    enforcer = StatefulEnforcer()
    first.register(
        agent_id,
        containment=ContainmentController(first_runtime, enforcers=[enforcer]),
    )
    old_lease = first_runtime.acquire_lease()
    assert old_lease is not None

    managed = first._managed(agent_id)
    original_contain = managed.containment.contain

    def contain_then_crash():
        report = original_contain()
        raise SystemExit("simulated crash after runtime and external containment")

    managed.containment.contain = contain_then_crash
    with pytest.raises(SystemExit, match="after runtime and external containment"):
        first.contain(agent_id)

    # The fence and runtime transition committed, but the incident write did not.
    assert fences.get(agent_id).containment_epoch == 1
    assert first_runtime.state is RuntimeState.CONTAINED
    assert first_runtime.epoch == 1
    assert incidents.latest_for_agent(agent_id) is None
    assert external_state["contained"] is True
    assert not first_runtime.lease_valid(old_lease)

    # A fresh service reconstructs the missing incident from the durable fence.
    restarted = ContainmentService(
        incidents=IncidentRegistry(incident_path),
        fences=RuntimeFenceRegistry(fence_path),
    )
    restarted_runtime = Runtime(agent_id)
    restarted.register(
        agent_id,
        containment=ContainmentController(
            restarted_runtime, enforcers=[StatefulEnforcer()]
        ),
    )
    incident = restarted.incident(agent_id)
    assert incident is not None
    assert incident.state is IncidentState.CONTAINED
    assert incident.containment_epoch == 1
    assert restarted_runtime.state is RuntimeState.CONTAINED
    assert restarted_runtime.epoch == 1
    assert restarted_runtime.acquire_lease() is None
    assert external_state["contained"] is True

    authorization = restarted.issue_recovery_authorization(agent_id)
    assert external_state["contained"] is True
    assert restarted.recover(agent_id, authorization) == 2
    assert restarted_runtime.state is RuntimeState.ACTIVE
    assert restarted_runtime.epoch == 2
    assert external_state["contained"] is False
    assert not restarted_runtime.lease_valid(old_lease)
