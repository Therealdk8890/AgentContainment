import pytest

from agent_containment.agent_tree import AgentTree
from agent_containment.runtime import RuntimeState


def test_containment_propagates_to_registered_descendants():
    tree = AgentTree()
    root = tree.register_root("root", {"network", "storage"})
    child = tree.spawn("root", "child")
    grandchild = tree.spawn("child", "grandchild")

    contained = tree.contain("root")

    assert contained == ["root", "child", "grandchild"]
    assert root.runtime.state is RuntimeState.CONTAINED
    assert child.runtime.state is RuntimeState.CONTAINED
    assert grandchild.runtime.state is RuntimeState.CONTAINED


def test_contained_parent_cannot_spawn_child():
    tree = AgentTree()
    tree.register_root("root")
    tree.contain("root")

    with pytest.raises(RuntimeError, match="cannot spawn"):
        tree.spawn("root", "child")


def test_capabilities_are_never_gained_by_child():
    tree = AgentTree()
    root = tree.register_root("root", {"network", "storage"})
    child = tree.spawn("root", "child", {"network", "admin"})

    assert child.containment.capabilities.capabilities == {"network"}
    assert "admin" not in child.containment.capabilities.capabilities
    assert root.containment.capabilities.capabilities == {"network", "storage"}


def test_spawn_race_with_parent_containment_has_no_orphan_escape():
    tree = AgentTree()
    tree.register_root("root", {"network"})
    barrier = __import__("threading").Barrier(2)
    created = []

    def spawn():
        barrier.wait()
        try:
            created.append(tree.spawn("root", "child"))
        except RuntimeError:
            pass

    def contain():
        barrier.wait()
        tree.contain("root")

    import threading
    t1 = threading.Thread(target=spawn)
    t2 = threading.Thread(target=contain)
    t1.start()
    t2.start()
    t1.join()
    t2.join()

    assert tree.nodes["root"].runtime.state is RuntimeState.CONTAINED
    if created:
        assert created[0].runtime.state is RuntimeState.CONTAINED
    else:
        assert "child" not in tree.nodes
