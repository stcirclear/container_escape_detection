/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
#ifndef __PROCRECORD_H
#define __PROCRECORD_H

#define TASK_COMM_LEN 16
#define NAME_MAX 255
#define ARGSIZE 128
#define TASK_COMM_LEN 16
#define TOTAL_MAX_ARGS 60
#define DEFAULT_MAXARGS 20
#define FULL_MAX_ARGS_ARR (TOTAL_MAX_ARGS * ARGSIZE)
#define INVALID_UID ((uid_t)-1)
#define BASE_EVENT_SIZE (size_t)(&((struct event *)0)->args)
#define EVENT_SIZE(e) (BASE_EVENT_SIZE + e->args_size)
#define LAST_ARG (FULL_MAX_ARGS_ARR - ARGSIZE)


struct process_event
{
	/* data */
	pid_t pid;
	unsigned long long cgroup_id;
	unsigned int pid_ns;
	unsigned int mnt_ns;
	unsigned long root_ino;
	int cap[2];
	
	pid_t ppid;
	unsigned int p_pid_ns;
	unsigned int p_mnt_ns;
	unsigned long p_root_ino;
	int p_cap[2];

	char comm[TASK_COMM_LEN];
	char filename[NAME_MAX];

	bool cap_err;
	bool ns_err;
	bool fs_err;
};

#endif /* __PROCRECORD_H */