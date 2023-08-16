// SPDX-License-Identifier: GPL-2.0-only
#define _GNU_SOURCE

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <sys/stat.h>
#include <test_progs.h>
#include <bpf/btf.h>
#include <bpf/bpf.h>

#include "cgroup_helpers.h"
#include "sockmem_policy.skel.h"

static int map_fd;
static int cg_nr;
struct {
	const char *path;
	int fd;
	unsigned long long id;
} cgs[] = {
	{ "/cg1" },
	{ "/cg2" },
};


static struct sockmem_policy *open_load_sockmem_policy_skel(void)
{
	struct sockmem_policy *skel;
	int err;

	skel = sockmem_policy__open();
	if (!ASSERT_OK_PTR(skel, "skel_open"))
		return NULL;

	err = sockmem_policy__load(skel);
	if (!ASSERT_OK(err, "skel_load"))
		goto cleanup;

	return skel;

cleanup:
	sockmem_policy__destroy(skel);
	return NULL;
}

static int set_cgroup_prio(unsigned long long cg_id, int prio)
{
	int err;

	err = bpf_map_update_elem(map_fd, &cg_id, &prio, BPF_ANY);
	ASSERT_EQ(err, 0, "update_map");
	return err;
}

static int prepare_cgroup_environment(void)
{
	int err;

	err = setup_cgroup_environment();
	if (err)
		goto clean_cg_env;
	for (int i = 0; i < cg_nr; i++) {
		err = cgs[i].fd = create_and_get_cgroup(cgs[i].path);
		if (!ASSERT_GE(cgs[i].fd, 0, "cg_create"))
			goto clean_cg_env;
		cgs[i].id = get_cgroup_id(cgs[i].path);
	}
	return 0;
clean_cg_env:
	cleanup_cgroup_environment();
	return err;
}

void test_sockmem_policy(void)
{
	struct sockmem_policy *skel;
	struct bpf_link *link;
	int err;
	//unsigned long long victim_cg_id;

	link = NULL;
	cg_nr = ARRAY_SIZE(cgs);

	skel = open_load_sockmem_policy_skel();
	err = sockmem_policy__attach(skel);
	if (!ASSERT_OK(err, "sockmem_policy__attach"))
		goto cleanup;

	map_fd = bpf_object__find_map_fd_by_name(skel->obj, "cg_map");
	if (!ASSERT_GE(map_fd, 0, "find map"))
		goto cleanup;

	err = prepare_cgroup_environment();
	if (!ASSERT_EQ(err, 0, "prepare cgroup env"))
		goto cleanup;

	set_cgroup_prio(cgs[0].id, 1);
	set_cgroup_prio(cgs[1].id, 0);

cleanup:
	bpf_link__destroy(link);
	sockmem_policy__destroy(skel);
	cleanup_cgroup_environment();
}
