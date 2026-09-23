#!/usr/bin/env bash
set -euo pipefail

command -v clang >/dev/null || { echo "clang is required" >&2; exit 1; }
command -v pkg-config >/dev/null || { echo "pkg-config is required" >&2; exit 1; }
pkg-config --exists libbpf || { echo "libbpf development package is required" >&2; exit 1; }

mkdir -p build
ARCH_INCLUDE="/usr/include/$(dpkg-architecture -qDEB_HOST_MULTIARCH 2>/dev/null || echo x86_64-linux-gnu)"
clang -O2 -g -target bpf -I"${ARCH_INCLUDE}" -c ebpf/agent_containment_egress.bpf.c -o build/agent_containment_egress.bpf.o
cc -O2 -Wall -Wextra ebpf/ctl.c -o build/agent_containment_ebpf_ctl $(pkg-config --cflags --libs libbpf)

echo "Built build/agent_containment_egress.bpf.o"
echo "Built build/agent_containment_ebpf_ctl"