#include <vmlinux.h>
#include "sysrecord.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

const volatile bool filter_cg = false;
const volatile unsigned char filter_report_times = 0;
const volatile pid_t targ_pid = 0;
const volatile pid_t targ_ppid = 0;
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
	__type(key, u32);				 // PID
	__type(value, u8[MAX_SYSCALLS]); // syscall IDs
} syscalls SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, u32);				 
	__type(value, struct syscall_event);
} syscall_heap SEC(".maps");

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

void __always_inline submit_event(void* ctx, struct task_struct *task, u32 pid, u64 mntns, u32 syscall_id, unsigned char times) {
    // submit event to perf buffer
	struct syscall_event *event;
	u32 zero = 0;
	event = bpf_map_lookup_elem(&syscall_heap, &zero);
	if (!event)
		return;

	event->pid = pid;
	event->ppid = BPF_CORE_READ(task, real_parent, tgid);
	event->mntns = mntns;
	event->syscall_id = syscall_id;
	event->occur_times = times;
	bpf_get_current_comm(&event->comm, sizeof(event->comm));

	bpf_perf_event_output(ctx, &syscall_event_pb, BPF_F_CURRENT_CPU, event, sizeof(*event));
	
}


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

	// 分析进程权限关系
	// 如果有传入的参数，则进行过滤，否则不过滤
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

	mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	if (mntns == 0)
		return 0;
	
	u8 *const syscall_value = bpf_map_lookup_elem(&syscalls, &pid);
	if(syscall_value)
	{
		if (syscall_value[syscall_id] == 0) {
            // submit event at first time
            submit_event(args, task, pid, mntns, syscall_id, 1);
			syscall_value[syscall_id] = 1;
            return 0;
        }
        else if (filter_report_times){
            if( syscall_value[syscall_id] >= filter_report_times) {
                // reach times, submit event
                submit_event(args, task, pid, mntns, syscall_id, syscall_value[syscall_id]);
				//syscall_value[syscall_id]++;
                syscall_value[syscall_id] = 1;
            } else {
                syscall_value[syscall_id]++;
            }
        } else if (min_duration_ns) {
            u64 ts = bpf_ktime_get_ns();
            if (syscall_value[syscall_id] < 255) syscall_value[syscall_id]++;
            if (ts - last_ts < min_duration_ns)
                return 0;
            last_ts = ts;
            submit_event(args, task, pid, mntns, syscall_id, syscall_value[syscall_id]);
            syscall_value[syscall_id] = 1;
        }
	}
	else
	{
		// 进程刚创建
		submit_event(args, task, pid, mntns, syscall_id, 1);
		static const unsigned char init[MAX_SYSCALLS];		
		bpf_map_update_elem(&syscalls, &pid, &init, BPF_ANY);
		
		u8 *const value = bpf_map_lookup_elem(&syscalls, &pid);
        if (!value)
        {
            // Should not happen, we updated the element straight ahead
            return 0;
        }
        value[syscall_id] = 1;
	}
	
	return 0;
}