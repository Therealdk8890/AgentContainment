from __future__ import annotations

import pytest

it = pytest.importorskip("interleave_test")


class BindingModel:
    """Reference model for the destination-binding epoch boundary."""

    def __init__(self) -> None:
        self.epoch = 1
        self.contained = False
        self.installed_epoch: int | None = None

    def contain(self) -> None:
        self.contained = True
        self.epoch += 1

    def bind(self) -> bool:
        observed_epoch = self.epoch

        # Resolution/translation is deliberately outside the final
        # controller-owned commit boundary. A real provider may do expensive
        # work here, so the epoch must be revalidated at installation.
        with it.no_interleave():
            if self.contained or observed_epoch != self.epoch:
                return False
            self.installed_epoch = observed_epoch
            return True


@it.interleave(iterations=100, seed=0, strategy="dfs", max_preemptions=1)
def test_destination_binding_cannot_cross_containment_epoch():
    """A binding observed in an old epoch must not become effective later."""

    model = BindingModel()

    with it.no_interleave():
        assert model.epoch == 1
        assert model.bind() is True
        model.installed_epoch = None
        model.contained = False

    outcomes: list[str] = []

    def bind():
        if model.bind():
            outcomes.append("bound")
        else:
            outcomes.append("stale")

    def contain():
        model.contain()
        outcomes.append("contained")

    worker = it.spawn(bind, name="bind")
    blocker = it.spawn(contain, name="contain")
    worker.join()
    blocker.join()

    assert sorted(outcomes) in (["bound", "contained"], ["contained", "stale"])

    if "stale" in outcomes:
        assert model.installed_epoch is None
    else:
        assert model.installed_epoch == model.epoch == 2
        assert model.contained is True
