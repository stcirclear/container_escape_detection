// SPDX-License-Identifier: GPL-2.0
// Copyright (c) 2019 Facebook
// Copyright (c) 2020 Netflix
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include "opensnoop.h"

#include "common_structs.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/errno.h>

const volatile pid_t targ_pid = 0;
const volatile pid_t targ_ppid = 0;
const volatile pid_t targ_tgid = 0;
const volatile uid_t targ_uid = 0;
const volatile bool targ_failed = false;
const volatile bool intercept = false;

#define MAX_ENTRIES 8 * 1024
#define NAME_MAX 255

// struct file_path {
//     unsigned char path[NAME_MAX];
// };

// struct callback_ctx {
//     unsigned char *path;
//     bool found;
// };

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} events SEC(".maps");

struct
{
	/* data */
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, pid_t);	  // PPID
	__type(value, pid_t); // PID
} pid_map SEC(".maps");

// struct
// {
// 	/* data */
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__uint(max_entries, 256);
// 	__type(key, u32);
// 	__type(value, struct file_path);
// 	__uint(pinning, LIBBPF_PIN_BY_NAME);
// } denied_access_files SEC(".maps");


// static u64 cb_check_path(struct bpf_map *map, u32 *key, struct file_path *map_path, struct callback_ctx *ctx) {
// 	bpf_printk("checking ctx->found: %d, path: map_path: %s, ctx_path: %s", ctx->found, map_path->path, ctx->path);

// 	size_t size = strlen(map_path->path, NAME_MAX);
// 	if (strcmp(map_path->path, ctx->path, size) == 0) {
// 		ctx->found = 1;
// 	}

// 	return 0;
// }

SEC("lsm/file_open")
int BPF_PROG(file_open, struct file *file)
{
	int ret = 0;
	struct task_struct *current_task;
	struct mnt_namespace *mnt_ns;
	struct nsproxy *nsproxy;
	u64 id = bpf_get_current_pid_tgid();
	// * use kernel terminology here for tgid/pid:
	u32 tgid = id >> 32;
	u32 pid = id;
	pid_t ppid;
	ppid = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), real_parent, tgid);

	if (targ_pid != 0)
	{
		// 1. 初始化：如果当前pid == targ_pid，则把其ppid也加入map
		pid_t tmp_pid;
		tmp_pid = targ_pid;
		bpf_map_update_elem(&pid_map, &tmp_pid, &tmp_pid, BPF_NOEXIST);
		tmp_pid = targ_ppid;
		bpf_map_update_elem(&pid_map, &tmp_pid, &tmp_pid, BPF_NOEXIST);
		
		// 2. 如果当前进程的父进程是否在pid_map，则将当前进程加入pid_map
		if (bpf_map_lookup_elem(&pid_map, &ppid))
		{
			bpf_map_update_elem(&pid_map, &pid, &pid, BPF_NOEXIST);
		}
		// 3. 如果当前进程及父进程都不在pid_map，则返回
		if (bpf_map_lookup_elem(&pid_map, &pid) == NULL && bpf_map_lookup_elem(&pid_map, &ppid) == NULL)
		{
			return 0;
		}
	}

	// bpf_printk("open: %d, targ_pid : %d\n", pid, targ_pid);
	unsigned int inum;
	current_task = (struct task_struct *)bpf_get_current_task();
	BPF_CORE_READ_INTO(&nsproxy, current_task, nsproxy);
	BPF_CORE_READ_INTO(&mnt_ns, nsproxy, mnt_ns);
	BPF_CORE_READ_INTO(&inum, mnt_ns, ns.inum);

	struct event e = {};
	e.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
	e.uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&e.comm, sizeof(e.comm));

	if (bpf_d_path(&file->f_path, e.fname, NAME_MAX) < 0)
	{
		return 0;
	}

	const unsigned char* blackname = "/home/test.c";
	size_t sz = strlen(blackname, NAME_MAX);
	if (strcmp(e.fname, blackname, sz) == 0)
	{
		bpf_printk("Warning: %s is opened\n", blackname);
		if (intercept)
		{
			ret = -EPERM;
			goto out;
		}
	}
	blackname = "/etc/shadow";
	sz = strlen(blackname, NAME_MAX);
	if (strcmp(e.fname, blackname, sz) == 0)
	{
		bpf_printk("Warning: %s is opened\n", blackname);
		if (intercept)
		{
			ret = -EPERM;
			goto out;
		}
	}
	blackname = "/proc/sysrq-trigger";
	sz = strlen(blackname, NAME_MAX);
	if (strcmp(e.fname, blackname, sz) == 0)
	{
		bpf_printk("Warning: %s is opened\n", blackname);
		if (intercept)
		{
			ret = -EPERM;
			goto out;
		}
	}

out:
	e.flags = 0;
	e.ret = ret;
	bpf_perf_event_output((void *)ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return ret;
}

SEC("lsm/sb_mount")
int BPF_PROG(restricted_mount, const char *dev_name, const struct path *path,
				const char *type, unsigned long flags, void *data, int ret_prev)
{
	int ret = 0;
	int index = 0;
	unsigned int inum;
	struct task_struct *current_task;
	struct mnt_namespace *mnt_ns;
	struct nsproxy *nsproxy;

	u64 id = bpf_get_current_pid_tgid();
	u32 tgid = id >> 32;
	u32 pid = id;
	pid_t ppid;
	ppid = BPF_CORE_READ((struct task_struct *)bpf_get_current_task(), real_parent, tgid);
	
	if (targ_pid != 0)
	{
		// 1. 初始化：如果当前pid == targ_pid，则把其ppid也加入map
		pid_t tmp_pid;
		tmp_pid = targ_pid;
		bpf_map_update_elem(&pid_map, &tmp_pid, &tmp_pid, BPF_NOEXIST);
		tmp_pid = targ_ppid;
		bpf_map_update_elem(&pid_map, &tmp_pid, &tmp_pid, BPF_NOEXIST);

		// 2. 如果当前进程的父进程是否在pid_map，则将当前进程加入pid_map
		if (bpf_map_lookup_elem(&pid_map, &ppid))
		{
			bpf_map_update_elem(&pid_map, &pid, &pid, BPF_NOEXIST);
		}
		// 3. 如果当前进程及父进程都不在pid_map，则返回
		if (bpf_map_lookup_elem(&pid_map, &pid) == NULL && bpf_map_lookup_elem(&pid_map, &ppid) == NULL)
		{
			return 0;
		}
	}
	
	current_task = (struct task_struct *)bpf_get_current_task();
	// struct task_struct *parent_task = BPF_CORE_READ(current_task, real_parent);

	BPF_CORE_READ_INTO(&nsproxy, current_task, nsproxy);
	BPF_CORE_READ_INTO(&mnt_ns, nsproxy, mnt_ns);
	BPF_CORE_READ_INTO(&inum, mnt_ns, ns.inum);

	struct event e = {};
	e.pid = (u32)(bpf_get_current_pid_tgid() >> 32);
	e.uid = bpf_get_current_uid_gid();
	bpf_get_current_comm(&e.comm, sizeof(e.comm));
	// bpf_probe_read_kernel_str(&event.parent_task, sizeof(event.parent_task), &parent_task->comm);
	bpf_probe_read_kernel_str(&e.fname, sizeof(e.fname), dev_name);

	const unsigned char* blackname = "/var/run/docker.sock";
	size_t sz = strlen(blackname, NAME_MAX);
	if (strcmp(e.fname, blackname, sz) == 0)
	{
		bpf_printk("Warning: %s is mounted\n", blackname);
		if (intercept)
		{
			ret = -EPERM;
			goto out;
		}
	}
	blackname = "/var/log";
	sz = strlen(blackname, NAME_MAX);
	if (strcmp(e.fname, blackname, sz) == 0)
	{
		bpf_printk("Warning: %s is mounted\n", blackname);
		if (intercept)
		{
			ret = -EPERM;
			goto out;
		}
	}
	blackname = "/dev/sda3";
	sz = strlen(blackname, NAME_MAX);
	if (strcmp(e.fname, blackname, sz) == 0)
	{
		bpf_printk("Warning: %s is mounted\n", blackname);
		if (intercept)
		{
			ret = -EPERM;
			goto out;
		}
	}

out:
	e.flags = 0;
	e.ret = ret;
	bpf_perf_event_output((void *)ctx, &events, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return ret;
}

char LICENSE[] SEC("license") = "GPL";
