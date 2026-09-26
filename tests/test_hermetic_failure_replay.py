from __future__ import annotations

from pathlib import Path

import pytest

hermetic = pytest.importorskip("hermetic")

from agent_containment.containment import ContainmentController
from agent_containment.control import ContainmentService
from agent_containment.enforcer import EnforcementResult, EnforcementStatus
from agent_containment.incident_state import IncidentRegistry
from agent_containment.runtime import RuntimeState
from agent_containment.runtime_fence import RuntimeFenceRegistry


class VerifiedEnforcer:
    name = "hermetic-failure-provider"

    def contain(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED, "contained")

    def verify_contained(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.ENFORCED, "verified")

    def release(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.RELEASED, "released")

    def verify_released(self, agent_id):
        return EnforcementResult(self.name, EnforcementStatus.RELEASED, "verified")


class FailingIncidentRegistry(IncidentRegistry):
    def record_containment(self, *args, **kwargs):
        raise OSError("injected incident persistence failure")


def test_containment_fence_survives_incident_persistence_failure_and_replay():
    with hermetic.sandbox(
        seed=42,
        fs="isolate",
        now="2026-01-01T00:00:00+00:00",
    ):
        fence_path = Path("runtime-fence.json")
        fences = RuntimeFenceRegistry(fence_path)
        failing_incidents = FailingIncidentRegistry()

        service = ContainmentService(
            incidents=failing_incidents,
            fences=fences,
        )
        runtime = service.register("agent-1")
        service.configure_containment(
            "agent-1",
            ContainmentController(runtime, enforcers=[VerifiedEnforcer()]),
        )

        report = service.contain("agent-1")

        assert runtime.state is RuntimeState.CONTAINED
        assert not runtime.can_execute
        assert report.epoch == 1
        assert not report.durable
        assert report.persistence_failures

        durable_fence = fences.get("agent-1")
        assert durable_fence is not None
        assert durable_fence.containment_epoch == report.epoch

        # Rebuild the controller from the same hermetic filesystem. The
        # persisted fence is authoritative even though incident persistence
        # produced no recoverable incident record.
        fresh_fences = RuntimeFenceRegistry(fence_path)
        fresh_service = ContainmentService(
            incidents=IncidentRegistry(),
            fences=fresh_fences,
        )
        fresh_runtime = fresh_service.register("agent-1")

        assert fresh_runtime.state is RuntimeState.CONTAINED
        assert fresh_runtime.epoch == report.epoch
        assert not fresh_runtime.can_execute
