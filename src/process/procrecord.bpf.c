// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include "procrecord.h"

#define MAX_ENTRIES 8 * 1024

const volatile bool filter_cg = false;
const volatile bool ignore_failed = true;
const volatile bool intercept = false;

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

const volatile pid_t target_pid = 0;
const volatile pid_t target_ppid = 0;

SEC("tracepoint/sched/sched_process_exec")
int tracepoint__sched__sched_process_exec(struct trace_event_raw_sched_process_exec *ctx)
{
	pid_t pid, ppid;
	char fname_off;
	struct task_struct *task;
	struct process_event e = {};

	/* Step 1: 获取进程上下文信息task */
	task = (struct task_struct *)bpf_get_current_task();
	pid = bpf_get_current_pid_tgid() >> 32;
	ppid = BPF_CORE_READ(task, real_parent, tgid);

	// 分析进程权限关系
	// 如果有传入的参数，则进行过滤，否则不过滤
	if (target_pid != 0)
	{
		// 1. 初始化：如果当前pid == target_pid，则把其ppid也加入map
		pid_t tmp_pid;
		tmp_pid = target_pid;
		bpf_map_update_elem(&pid_map, &tmp_pid, &tmp_pid, BPF_NOEXIST);
		tmp_pid = ppid;
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

	unsigned int level = BPF_CORE_READ(task, thread_pid, level);
	pid_t ns_pid = BPF_CORE_READ(task, thread_pid, numbers[level].nr);

	// 用跟踪点上下文中的数据填充e
	e.cap_err = false;
	e.fs_err = false;
	e.pid = pid;
	e.ppid = ppid;
	bpf_get_current_comm(&e.comm, sizeof(e.comm));
	fname_off = ctx->__data_loc_filename & 0xFFFF;
	bpf_probe_read_str(e.filename, sizeof(e.filename), (void *)ctx + fname_off);
	e.pid_ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children, ns.inum);
	e.mnt_ns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	
	// 权限比较,若发生提权事件则cap_err=true
	kernel_cap_t p_cap = BPF_CORE_READ(task, real_parent, cred, cap_effective);
	kernel_cap_t cap = BPF_CORE_READ(task, cred, cap_effective);
	e.p_cap[0] = p_cap.cap[0];
	e.p_cap[1] = p_cap.cap[1];

	e.cap[0] = cap.cap[0];
	e.cap[1] = cap.cap[1];


	bpf_printk("%s p_cap:%x %x\n", e.comm, e.p_cap[0], e.p_cap[1]);
	bpf_printk("%s   cap:%x %x\n", e.comm, e.cap[0], e.cap[1]);
	if(e.p_cap[0] < e.cap[0] || e.p_cap[1] < e.cap[1]) {
		bpf_printk("!ERROR! pid: %d capability elevated!\n", e.pid);
		e.cap_err = true;
		if (intercept)
		{
			bpf_send_signal(9);
		}
	}

	e.p_pid_ns = BPF_CORE_READ(task, real_parent, nsproxy, pid_ns_for_children, ns.inum);
	e.p_mnt_ns = BPF_CORE_READ(task, real_parent, nsproxy, mnt_ns, ns.inum);
	bpf_printk("%s p_ns:%x %x\n", e.comm, e.pid_ns, e.mnt_ns);
	bpf_printk("%s   ns:%x %x\n", e.comm, e.p_pid_ns, e.p_mnt_ns);
	if(e.p_pid_ns > e.pid_ns || e.p_mnt_ns > e.mnt_ns) {
		bpf_printk("!ERROR! pid: %d namespace changed!\n", e.pid);
		e.ns_err = true;
		if (intercept)
		{
			bpf_send_signal(9);
		}
	}
	

	// fs_struct *fs
	e.root_ino = BPF_CORE_READ(task, fs, root.dentry, d_inode, i_ino);
	e.p_root_ino = BPF_CORE_READ(task, real_parent, fs, root.dentry, d_inode, i_ino);
	bpf_printk("%s p_ino:%lu\n", e.comm, e.p_root_ino);
	bpf_printk("%s   ino:%lu\n", e.comm, e.root_ino);
	// 工作目录比较
	if(e.p_root_ino > e.root_ino){
		bpf_printk("!ERROR! pid: %d root fs changed!\n", e.pid);
		e.fs_err = true;
		if (intercept)
		{
			bpf_send_signal(9);
		}
	}
	

	// 发送样本到BPF perfbuf		
	bpf_perf_event_output(ctx, &process_event_pb, BPF_F_CURRENT_CPU, &e, sizeof(e));
	return 0;
}

// SEC("tracepoint/sched/sched_process_fork")

char LICENSE[] SEC("license") = "GPL";
