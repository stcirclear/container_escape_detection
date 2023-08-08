#ifndef __SYSRECORD_H
#define __SYSRECORD_H

#define TASK_COMM_LEN 64
#define MAX_ENTRIES 8 * 1024
#define MAX_SYSCALLS 1024
#define MAX_COMM_LEN 64

// if pid is not set, this message is the first time a syscall happends in a process;
// if target_pid or cgroups is set, this message is all syscalls
struct syscall_event
{
	pid_t pid;
	pid_t ppid;
	unsigned int syscall_id;
	unsigned int mntns;
	char comm[TASK_COMM_LEN];

	// long unsigned int args[6];
};

#endif /* __SYSRECORD_H */
