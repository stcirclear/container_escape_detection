// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "procrecord.h"

#define MAX_ENTRIES 8 * 1024

const volatile bool filter_cg = false;
const volatile bool ignore_failed = true;

static const struct process_event empty_event = {};

struct
{
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct process_event);
} processes SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} process_event_pb SEC(".maps"); // perf buffer

struct
{
	/* data */
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, pid_t);	  // PPID
	__type(value, pid_t); // PID
} pid_map SEC(".maps");

const pid_t target_pid = 0;
//  volatile

SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	pid_t pid, ppid;
	char fname_off;
	char comm[TASK_COMM_LEN];
	struct task_struct *task;
	struct process_event *e;
	u32 zero = 0;
	task = (struct task_struct *)bpf_get_current_task();

	pid = bpf_get_current_pid_tgid() >> 32;
	ppid = BPF_CORE_READ(task, real_parent, tgid);

	if (target_pid)
	{
		/* first time: add filter_pid to pid_map */
		if (bpf_map_lookup_elem(&pid_map, &target_pid) == NULL)
		{
			bpf_map_update_elem(&pid_map, &target_pid, &zero, BPF_ANY);
		}

		/* ppid in pid_map, add pid to pid_map*/
		if (bpf_map_lookup_elem(&pid_map, &ppid))
		{
			bpf_map_update_elem(&pid_map, &pid, &zero, BPF_ANY);
		}
		else
		{
			return 0;
		}
	}

	e = bpf_map_lookup_elem(&processes, &zero);
	if (!e)
		return 0;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->exit_event = false;
	e->pid = pid;
	e->ppid = ppid;
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(e->filename, sizeof(e->filename), (void *)ctx + fname_off);

	bpf_printk("hello, world.\n");
	bpf_printk("%s %d\n", e->comm, e->pid);

	bpf_perf_event_output(ctx, &process_event_pb, BPF_F_CURRENT_CPU, e, sizeof(*e));
	return 0;
}

SEC("tracepoint/sched/sched_process_exit")
int tracepoint__sched__sched_process_exit(struct trace_event_raw_sched_process_template *ctx)
{
	struct task_struct *task;
	struct process_event *e;
	u64 id;
	pid_t pid, tid, ppid;

	task = (struct task_struct *)bpf_get_current_task();
	id = bpf_get_current_pid_tgid();
	pid = id >> 32;
	ppid = BPF_CORE_READ(task, real_parent, tgid);
	tid = (pid_t)id;

	if (target_pid)
	{
		// first time: add filter_pid to pid_map
		u32 zero = 0;
		if (bpf_map_lookup_elem(&pid_map, &target_pid) == NULL)
		{
			bpf_map_update_elem(&pid_map, &target_pid, &zero, BPF_ANY);
		}

		// ppid in pid_map, add pid to pid_map
		if (bpf_map_lookup_elem(&pid_map, &ppid))
		{
			bpf_map_update_elem(&pid_map, &pid, &zero, BPF_ANY);
		}
		else
		{
			return 0;
		}
	}

	e = bpf_map_lookup_elem(&processes, &pid);
	if (!e)
		return 0;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->exit_event = true;
	e->prio = ctx->prio; // priority

	bpf_perf_event_output(ctx, &process_event_pb, BPF_F_CURRENT_CPU, e, sizeof(*e));
	return 0;
}

// SEC("tracepoint/sched/sched_process_fork")

char LICENSE[] SEC("license") = "GPL";