# Incident → Regression Fixtures

AgentContainment closes the governance loop by turning a contained incident into
a deterministic release-test input:

`Incident → Evidence → RegressionFixture → Release Gate`

## Fixture contract

`RegressionFixture` preserves:

- incident identity;
- agent identity and version;
- task and execution context;
- the observed action sequence;
- the policy decision;
- references to controller/evidence records;
- the containment result;
- the expected future behavior.

Fixtures use canonical JSON serialization and a SHA-256 content digest. The
`fixture_id` is derived from the fixture inputs, so equivalent fixtures receive
the same identity regardless of mapping key order.

## Release-gate usage

A CI test can replay the relevant authorization logic and compare the resulting
policy decision and containment requirement with the fixture:

```python
from agent_containment.regression import assert_regression

assert_regression(
    fixture,
    policy_decision=current_decision,
    containment_required=current_containment_required,
)
```

A mismatch fails the release test. The regression layer does not invoke an
enforcer, release containment, or grant recovery authority.

## Security boundary

Regression fixtures are downstream artifacts.

```text
AgentContainment CONTROL
        |
        | incident/evidence
        v
RegressionFixture
        |
        v
CI / release gate
```

The CI gate can reject a build when previously observed behavior changes, but it
cannot change runtime authorization or containment state.

The fixture is also not a claim that production is safe. It records a known
failure mode and makes that failure mode testable again.

## Recommended lifecycle

1. Containment produces controller-owned lifecycle events.
2. Evidence records bind the incident to enforcement and observation.
3. An operator or CI preparation step creates a regression fixture.
4. The fixture is committed to the repository as a reviewable artifact.
5. CI replays the relevant scenario.
6. A changed policy decision or containment requirement fails the gate.
7. The fixture remains historical engineering knowledge even if the
   implementation later changes.

The intended result is that an incident does not merely become a postmortem. It
becomes a permanent test against recurrence.