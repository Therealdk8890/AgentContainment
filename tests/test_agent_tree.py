import pytest

from agent_containment.agent_tree import AgentTree
from agent_containment.runtime import RuntimeState


def test_child_inherits_parent_capabilities():
    tree = AgentTree()
    tree.register_root("parent", {"db.read", "network"})
    child = tree.spawn("parent", "child")

    assert child.containment.capabilities.capabilities == {"db.read", "network"}


def test_child_capabilities_can_be_restricted():
    tree = AgentTree()
    tree.register_root("parent", {"db.read", "network", "shell"})
    child = tree.spawn("parent", "child", {"db.read", "network"})

    assert child.containment.capabilities.capabilities == {"db.read", "network"}


def test_containment_propagates_to_child_and_grandchild():
    tree = AgentTree()
    tree.register_root("parent", {"db"})
    tree.spawn("parent", "child")
    tree.spawn("child", "grandchild")

    contained = tree.contain("parent")

    assert contained == ["parent", "child", "grandchild"]
    assert tree.nodes["parent"].runtime.state is RuntimeState.CONTAINED
    assert tree.nodes["child"].runtime.state is RuntimeState.CONTAINED
    assert tree.nodes["grandchild"].runtime.state is RuntimeState.CONTAINED
    assert tree.nodes["grandchild"].containment.capabilities.capabilities == set()


def test_contained_parent_cannot_spawn_child():
    tree = AgentTree()
    tree.register_root("parent", {"db"})
    tree.contain("parent")

    with pytest.raises(RuntimeError):
        tree.spawn("parent", "child")


def test_containment_blocks_descendant_capabilities():
    tree = AgentTree()
    tree.register_root("parent", {"db", "network"})
    child = tree.spawn("parent", "child")

    tree.contain("parent")

    assert child.containment.capabilities.capabilities == set()
    assert not child.runtime.can_execute


def test_unknown_agent_is_rejected():
    tree = AgentTree()

    with pytest.raises(KeyError):
        tree.contain("missing")
