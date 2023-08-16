// SPDX-License-Identifier: GPL-2.0-only
#include <vmlinux.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_helpers.h>

char _license[] SEC("license") = "GPL";
struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, int);
	__type(value, int);
	__uint(max_entries, 24);
} cg_map SEC(".maps");

/*
enum {
	NO_BPF_POLICY,
	BPF_SOCKMEM_PRESSURE,
};
*/

static __always_inline u64 task_cgroup_id(struct sock *sk)
{
	struct kernfs_node *node;

	if (!sk)
		return 0;

	node = sk->sk_memcg->css.cgroup->kn;

	return node->id;
}

SEC("fmod_ret/bpf_sockmem_cg_policy")
int BPF_PROG(bpf_sockmem_cg_policy, struct sock *sk)
{
	u64 chosen_cg_id;
	int *val;

	chosen_cg_id = task_cgroup_id(sk);
	val = bpf_map_lookup_elem(&cg_map, &chosen_cg_id);
	if (val)
		return BPF_SOCKMEM_PRESSURE;

	return NO_BPF_POLICY;
}
