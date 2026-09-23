#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * Drop all egress traffic from the cgroup this program is attached to.
 * The controller attaches this program only when containment is active.
 */
SEC("cgroup_skb/egress")
int agent_containment_egress(struct __sk_buff *skb)
{
    return 0;
}

char LICENSE[] SEC("license") = "GPL";