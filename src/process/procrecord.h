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
	pid_t ppid;
	unsigned long long cgroup_id;
	unsigned int user_namespace_id;
	unsigned int pid_namespace_id;
	unsigned int mount_namespace_id;

	char comm[TASK_COMM_LEN];
	char filename[NAME_MAX];

	bool cap_err;
};

#endif /* __PROCRECORD_H */