#include <vmlinux.h>
#include "sysrecord.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

const volatile bool filter_cg = false;
const volatile unsigned char filter_report_times = 0;
const volatile pid_t filter_pid = 0;
const volatile unsigned long long min_duration_ns = 0;
volatile unsigned long long last_ts = 0;

static const struct syscall_event empty_event = {};

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

// 暂存需要提交的事件
struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);				// PID
	__type(value, struct syscall_event); 
} syscalls SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);				   // PID
	__type(value, char[MAX_COMM_LEN]); // command name
} commands SEC(".maps");

// perf buffer
struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	// __uint(max_entries, MAX_ENTRIES);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} syscall_event_pb SEC(".maps");

struct
{
	/* data */
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);	// PPID
	__type(value, u32); // PID
} pid_map SEC(".maps");


SEC("tracepoint/raw_syscalls/sys_enter")
int sys_enter(struct trace_event_raw_sys_enter *args)
{
	pid_t pid, ppid;
	u32 syscall_id;
	u64 mntns;
	struct task_struct *task;
	struct syscall_event *e;

	/* Step 1: 获取进程上下文信息task */
	syscall_id = args->id;
	if (syscall_id < 0 || syscall_id >= MAX_SYSCALLS)
	{
		return 0;
	}

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

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
			bpf_map_update_elem(&pid_map, &pid, &pid, BPF_NOEXIST);

		// 3. 如果当前进程及父进程都不在pid_map，则返回
		if (bpf_map_lookup_elem(&pid_map, &pid) == NULL && bpf_map_lookup_elem(&pid_map, &ppid) == NULL)
			return 0;
	}

	mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	if (mntns == 0)
		return 0;

	/* Step 3: 提交到perf buffer */ 
	if(bpf_map_update_elem(&syscalls, &pid, &empty_event, BPF_NOEXIST))
		return 0;
	
	e = bpf_map_lookup_elem(&syscalls, &pid);
	if (!e)
		return 0;
	
	e->pid = pid;
	e->ppid = ppid;
	e->mntns = mntns;
	e->syscall_id = syscall_id;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	
	bpf_perf_event_output(args, &syscall_event_pb, BPF_F_CURRENT_CPU, e, sizeof(*e));
	
	return 0;
}