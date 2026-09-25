#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/*
 * Drop all egress traffic from the cgroup this program is attached to.
 *
 * For cgroup_skb programs, a return value of 0 means DROP and 1 means
 * ALLOW. The controller attaches this program only when containment is
 * active, so the deny decision is made at the kernel networking hook rather
 * than by the agent's application code.
 */
SEC("cgroup_skb/egress")
int agent_containment_egress(struct __sk_buff *skb)
{
    (void)skb;
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
