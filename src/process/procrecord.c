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

static struct env
{
	bool verbose;
	bool exiting;
	char *cgroupspath;
	bool cg;
	pid_t pid;
	bool intercept;
} process_env = {

};

const char *argp_program_version = "procrecord 0.1";
const char *argp_program_bug_address =
	"https://github.com/stcirclear/container_escape_detection.git";
const char argp_program_doc[] =
	"Trace exec syscalls\n"
	"\n"
	"USAGE: ./procrecord -a alert/intercept [-h] [-p] [-c CG]\n"
	"\n"
	"EXAMPLES:\n"
	"   ./procrecord           # trace all process\n"
	"   ./procrecord -p {pid}  # trace pid and its child-process\n"
	"   ./procrecord -c CG     # Trace process under cgroupsPath CG\n"
	"   ./procrecord -a alert/intercept     # Trace process under cgroupsPath CG\n"
	;

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
		process_env.intercept = strcmp(arg, "alert") ? true : false;
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
		process_env.pid = (int)pid;
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

/* 响应函数 */
static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	FILE *fp;
	const struct process_event *e = data;
	
	fp = fopen("log/procrecord.log", "a");
	if (fp == NULL)
	{
		return;
	}
	
	if (e->cap_err)
	{
		fprintf(fp, "[ERROR] pid: %d cap changed!\n", e->pid);
	} else if (e->fs_err) {
		fprintf(fp, "[ERROR] pid: %d fs changed!\n", e->pid);
	} else if (e->ns_err) {
		fprintf(fp, "[ERROR] pid: %d ns changed!\n", e->pid);
	}
	fprintf(fp, "%-8s %-16s %-6d [0x%x] [0x%x] [0x%x %x] %-8lu\n", "PROC:", e->comm, e->pid, e->pid_ns, e->mnt_ns, e->cap[0], e->cap[1], e->root_ino);
	fprintf(fp, "%-8s %-16s %-6d [0x%x] [0x%x] [0x%x %x] %-8lu\n", "PPROC:", e->comm, e->ppid, e->p_pid_ns, e->p_mnt_ns, e->p_cap[0], e->p_cap[1], e->p_root_ino);
	fclose(fp);
}

static void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	printf("Debuge: In handle_lost_event\n");
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

	process_env.exiting = &exiting;

	if (!process_env.exiting)
	{
	 	fprintf(stderr, "process_env.exiting is not set.\n");
	 	return -1;
	}

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	obj = procrecord_bpf__open();
	if (!obj)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* 通过pid获取ppid */ 
	char cmd[128];
	char result[16];
	sprintf(cmd, "ps -elf |awk '$4=='%d'{print $5}'", process_env.pid);
	FILE *pipe = popen(cmd, "r");
	if(!pipe)
		return 0;
	
	char buffer[128] = {0};
	while(!feof(pipe))
	{
		if(fgets(buffer, 128, pipe))
			strcat(result, buffer);
	}
	pclose(pipe);

	pid_t ppid = atoi(result);

	/* initialize global data (filtering options) */
	obj->rodata->targ_pid = process_env.pid;
	obj->rodata->targ_ppid = ppid; 
	obj->rodata->intercept = process_env.intercept;

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
	
	// 创建log文件夹
	system("mkdir -p log");
	// 打印日志头
	FILE *fp;
	fp = fopen("log/procrecord.log", "a");
	if (fp == NULL)
	{
		return 0;
	}

	fprintf(fp, "%-8s %-16s %-6s %-12s %-12s %-16s %-8s\n", "[P]PROC", "COMM", "PID", "PID_NS", "MNT_NS", "CAP", "ROOT_INO");
	fclose(fp);

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