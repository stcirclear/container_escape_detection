// Based on process(8) from BCC by Brendan Gregg and others.
//
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <fcntl.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "procrecord.h"
#include "procrecord.skel.h"
#include "btf_helpers.h"
#include "trace_helpers.h"

#define PERF_BUFFER_PAGES 64
#define PERF_POLL_TIMEOUT_MS 100
#define MAX_ARGS_KEY 259

static volatile sig_atomic_t exiting = 0;
static volatile bool do_intercept;

static struct env
{
	bool verbose;
	bool exiting;
	char *cgroupspath;
	bool cg;
	pid_t target_pid;
} process_env = {

};

const char *argp_program_version = "procrecord 0.1";
const char *argp_program_bug_address =
	"https://github.com/stcirclear/container_escape_detection.git";
const char argp_program_doc[] =
	"Trace exec syscalls\n"
	"\n"
	"USAGE: procrecord [-h] [-p] [-c CG]\n"
	"\n"
	"EXAMPLES:\n"
	"   ./procrecord           # trace all process\n"
	"   ./procrecord -p        # trace pid and its child-process\n"
	"   ./procrecord -c CG     # Trace process under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{"action", 'a', "ACTION", 0, "do this action when bad things happen"},
	{"pid", 'p', "PID", 0, "trace this pid and its all child process"},
	{"cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace process in cgroup path"},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	pid_t pid;

	switch (key)
	{
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'a':
		do_intercept = strcmp(arg, "alert") ? true : false;
		break;
	case 'c':
		process_env.cgroupspath = arg;
		process_env.cg = true;
		break;
	case 'p':
		errno = 0;
		pid = atoi(arg);
		if (errno || pid < 0 || pid >= INT_MAX)
		{
			fprintf(stderr, "Invalid PID %s\n", arg);
			argp_usage(state);
		}
		process_env.target_pid = (int)pid;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}
/*
// 权限比较，函数待优化！！！
static int cap_check(pid_t p1, pid_t p2)
{
	int res = 0;
	FILE *file1, *file2;
	unsigned long cap1, cap2;
	char c[] = " ", c1[] = ":";
	char cmd[128], exist1[64], exist2[64], cap[64];
	sprintf(cmd, "ps -ef |grep %d |grep -v \" grep \" |wc -l", p1);
	file1 = popen(cmd, "r");
	sprintf(cmd, "ps -ef |grep %d |grep -v \" grep \" |wc -l", p2);
	file2 = popen(cmd, "r");
	if (file1 != NULL && file2 != NULL)
	{
		fgets(exist1, 64, file1);
		fgets(exist2, 64, file2);
	}
	if (atoi(exist1) != 0 && atoi(exist2) != 0)
	{
		memset(cmd, 0, 128);
		sprintf(cmd, "sudo cat /proc/%d/task/%d/status | grep CapEff", p1, p1);
		file1 = popen(cmd, "r");
		if (file1 != NULL)
		{
			fgets(cap, 64, file1);
			char *token, *token1;
			token = strtok(cap, c);
			token1 = strtok(token, c1);
			token1 = strtok(NULL, c1);
			cap1 = strtoul(token1, NULL, 16);
		}
		memset(cmd, 0, 128);
		memset(cap, 0, 64);
		sprintf(cmd, "sudo cat /proc/%d/task/%d/status | grep CapEff", p2, p2);
		file2 = popen(cmd, "r");
		if (file2 != NULL)
		{
			fgets(cap, 64, file2);
			char *token, *token1;
			token = strtok(cap, c);
			token1 = strtok(token, c1);
			token1 = strtok(NULL, c1);
			cap2 = strtoul(token1, NULL, 16);
		}
		// TODO: 这里比较cap值的大小以判断权限的大小，是否是正确的？不正确就还是要用“capsh --decode”解析
		if (cap1 <= cap2)
		{
			res = 1;
			// printf("OK\n");
		}
		else
		{
			res = -1;
		}
	}

	pclose(file1);
	pclose(file2);
	return res;
}
*/
static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !process_env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
	exiting = true;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	// TODO: 在这检查 & 响应
	FILE *fp;
	const struct process_event *e = data;
	if (e->cap_err)
	{
		if (do_intercept)
		{
			printf("Do kill\n");
		}
		else
		{
			printf("Do warning\n");
		}
		printf("[ERROR] pid: %d cap changed!\n", e->pid);
	} else if (e->fs_err) {
		printf("[ERROR] pid: %d fs changed!\n", e->pid);
	} else if (e->ns_err) {
		printf("[ERROR] pid: %d ns changed!\n", e->pid);
	}
	fp = fopen("procrecord.txt", "a");
	if (fp == NULL)
	{
		return;
	}
	fprintf(fp, "%-16s %-6d %-6d [%u] [%u] %s\n", e->comm, e->pid, e->ppid, e->pid_namespace_id, e->mount_namespace_id, e->filename);
	fclose(fp);
	// printf("%-16s %-6d %-6d [%u] [%u] %s\n", e->comm, e->pid, e->ppid, e->pid_namespace_id, e->mount_namespace_id, e->filename);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	LIBBPF_OPTS(bpf_object_open_opts, open_opts);
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct perf_buffer *pb = NULL;
	struct procrecord_bpf *obj;
	int err;
	int cgfd = -1;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// process_env.exiting = &exiting;

	// if (!process_env.exiting)
	// {
	// 	fprintf(stderr, "env.exiting is not set.\n");
	// 	return -1;
	// }

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	obj = procrecord_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* initialize global data (filtering options) */
	obj->rodata->filter_pid = process_env.target_pid;

	err = procrecord_bpf__load(obj);
	if (err)
	{
		fprintf(stderr, "failed to load BPF object: %d\n", err);
		goto cleanup;
	}

	err = procrecord_bpf__attach(obj);
	if (err)
	{
		fprintf(stderr, "failed to attach BPF programs\n");
		goto cleanup;
	}
	FILE *fp;
	fp = fopen("procrecord.txt", "a");
	if (fp == NULL)
	{
		return 0;
	}
	// printf("ok\n");
	fprintf(fp, "%-16s %-6s %-6s %-10s %-10s %3s %s\n", "PCOMM", "PID", "PPID", "PID_NS", "MNT_NS", "RET", "ARGS");
	fclose(fp);
	// printf("%-16s %-6s %-6s %-10s %-10s %3s %s\n", "PCOMM", "PID", "PPID", "PID_NS", "MNT_NS", "RET", "ARGS");

	/* setup event callbacks */
	pb = perf_buffer__new(bpf_map__fd(obj->maps.process_event_pb), PERF_BUFFER_PAGES,
						  handle_event, handle_lost_events, NULL, NULL);
	if (!pb)
	{
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}

	/* main: poll */
	while (!exiting)
	{
		err = perf_buffer__poll(pb, PERF_POLL_TIMEOUT_MS);
		if (err < 0 && err != -EINTR)
		{
			fprintf(stderr, "error polling perf buffer: %s\n", strerror(-err));
			goto cleanup;
		}
		/* reset err to return 0 if exiting */
		err = 0;
	}

cleanup:
	perf_buffer__free(pb);
	procrecord_bpf__destroy(obj);
	cleanup_core_btf(&open_opts);
	if (cgfd > 0)
		close(cgfd);

	return err != 0;
}