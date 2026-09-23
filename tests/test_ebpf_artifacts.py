from pathlib import Path


def test_ebpf_source_exists():
    source = Path("ebpf/agent_containment_egress.bpf.c")
    text = source.read_text()
    assert 'SEC("cgroup_skb/egress")' in text
    assert 'return 0;' in text


def test_ebpf_build_script_exists():
    script = Path("scripts/build_ebpf.sh")
    assert script.exists()
    assert "-target bpf" in script.read_text()


def test_ebpf_controller_exists():
    ctl = Path("ebpf/ctl.c")
    text = ctl.read_text()
    assert "bpf_program__attach_cgroup" in text
    assert "bpf_link__pin" in text