#include <vmlinux.h>
#include "sysrecord.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>

#define MAX_ENTRIES 8 * 1024
#define MAX_SYSCALLS 1024
#define MAX_COMM_LEN 64

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);				 // PID
	__type(value, u8[MAX_SYSCALLS]); // syscall IDs
} syscalls SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);				   // PID
	__type(value, char[MAX_COMM_LEN]); // command name
} commands SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	// __uint(max_entries, MAX_ENTRIES);
	__uint(key_size, sizeof(u32));
	__uint(value_size, sizeof(u32));
} syscall_event_pb SEC(".maps");

struct
{
	__uint(type, BPF_MAP_TYPE_CGROUP_ARRAY);
	__type(key, u32);
	__type(value, u32);
	__uint(max_entries, 1);
} cgroup_map SEC(".maps");

struct
{
	/* data */
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, MAX_ENTRIES);
	__type(key, u32);	// PPID
	__type(value, u32); // PID
} pid_map SEC(".maps");

const volatile bool filter_cg = false;
const volatile unsigned char filter_report_times = 0;
const volatile pid_t filter_pid = 0;
const volatile unsigned long long min_duration_ns = 0;
volatile unsigned long long last_ts = 0;

void __always_inline submit_event(void *ctx, struct task_struct *task, u32 pid, u64 mntns, u32 syscall_id, unsigned char times)
{
	// New element, throw event
	struct syscall_event *event;

	event = bpf_map_lookup_elem(&syscalls, &pid);
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
	// Sanity check
	u32 syscall_id = args->id;
	if (syscall_id < 0 || syscall_id >= MAX_SYSCALLS)
	{
		return 0;
	}

	u32 pid = bpf_get_current_pid_tgid() >> 32;

	if (filter_cg && !bpf_current_task_under_cgroup(&cgroup_map, 0))
		return 0;

	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

	if (filter_pid)
	{
		/* first time: add filter_pid to pid_map */
		u32 zero = 0;
		pid_t target_pid = filter_pid;
		// TODO:新建一个变量，不要修改这个filter_pid？？？
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

	u64 mntns = BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
	if (mntns == 0)
	{
		return 0;
	}

	// Update the command name if required
	char comm[MAX_COMM_LEN];
	bpf_get_current_comm(comm, sizeof(comm));
	if (bpf_map_lookup_elem(&commands, &comm) == NULL)
	{
		bpf_map_update_elem(&commands, &pid, &comm, BPF_ANY);
	}

	// Update the syscalls
	u8 *const syscall_count = bpf_map_lookup_elem(&syscalls, &pid);
	if (syscall_count)
	{
		if (syscall_count[syscall_id] == 0)
		{
			// submit event at first time
			submit_event(args, task, pid, mntns, syscall_id, 1);
			syscall_count[syscall_id] = 1;
			return 0;
		}
		else if (filter_report_times)
		{
			if (syscall_count[syscall_id] >= filter_report_times)
			{
				// reach times, submit event
				submit_event(args, task, pid, mntns, syscall_id, filter_report_times);
				syscall_count[syscall_id] = 1;
			}
			else
			{
				syscall_count[syscall_id]++;
			}
		}
		else if (min_duration_ns)
		{
			u64 ts = bpf_ktime_get_ns();
			if (syscall_count[syscall_id] < 255)
				syscall_count[syscall_id]++;
			if (ts - last_ts < min_duration_ns)
				return 0;
			last_ts = ts;
			submit_event(args, task, pid, mntns, syscall_id, syscall_count[syscall_id]);
			syscall_count[syscall_id] = 1;
		}
	}
	else
	{
		// submit event at first time
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