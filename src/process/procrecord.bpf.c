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
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1);
	__type(key, u32);
	__type(value, struct process_event);
} processes SEC(".maps");  // 暂存需要提交的事件

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

const volatile pid_t filter_pid = 0;

SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	pid_t pid, ppid;
	char fname_off;
	char comm[TASK_COMM_LEN];
	struct task_struct *task;
	struct process_event *e;
	u32 zero = 0;

	/* Step 1: 获取进程上下文信息task */
	task = (struct task_struct *)bpf_get_current_task();

	pid = bpf_get_current_pid_tgid() >> 32;
	ppid = BPF_CORE_READ(task, real_parent, tgid);

	/* step 2: 分析进程是否属于容器 */
	if (filter_pid)
	{
		pid_t target_pid = filter_pid;
		// 1. 先将target_pid加入pid_map
		bpf_map_update_elem(&pid_map, &target_pid, &target_pid, BPF_NOEXIST);
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

	/* Step 3: 提交到perf buffer*/ 
	if(bpf_map_update_elem(&processes, &pid, &empty_event, BPF_NOEXIST))
		return 0;

	e = bpf_map_lookup_elem(&processes, &pid);
	if (!e) 
		return 0;

	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	e->exit_event = false;
	e->pid = pid;
	e->ppid = ppid;
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(e->filename, sizeof(e->filename), (void *)ctx + fname_off);
	e->pid_namespace_id = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
	e->mount_namespace_id = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);

	bpf_perf_event_output(ctx, &process_event_pb, BPF_F_CURRENT_CPU, e, sizeof(*e));
	return 0;
}

// SEC("tracepoint/sched/sched_process_fork")

char LICENSE[] SEC("license") = "GPL";