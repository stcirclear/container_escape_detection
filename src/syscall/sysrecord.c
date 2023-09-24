#include "../utils/syscall_helpers.h"
#include <sys/syscall.h>
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>
#include <unistd.h>

#include "sysrecord.h"
#include "sysrecord.skel.h"

/* Tune the buffer size and wakeup rate. These settings cope with roughly
 * 50k opens/sec.
 */
#define PERF_BUFFER_PAGES 64
#define PERF_BUFFER_TIME_MS 10

/* Set the poll timeout when no events occur. This can affect -d accuracy. */
#define PERF_POLL_TIMEOUT_MS 300

struct syscall_env
{
	bool verbose;
	volatile bool *exiting;

	char *cgroupspath;
	// file cgroup
	bool filter_cg;
	pid_t targ_pid;
	// the min sample duration in ms
	long min_duration_ms;
	// the times syscall a process is sampled
	unsigned char filter_report_times;
	bool intercept;
} syscall_env = {
	.min_duration_ms = 100,
	.filter_report_times = 100
};

#define warn(...) fprintf(stderr, __VA_ARGS__)
const char *argp_program_version = "syscall 0.1";
const char *argp_program_bug_address =
	"https://github.com/stcirclear/container_escape_detection.git";
const char argp_program_doc[] =
	"Trace syscall\n"
	"\n"
	"USAGE: syscall -a alert/intercept [-p] [-c]\n"
	"\n"
	"EXAMPLES:\n"
	"   ./syscall           # trace all exec() syscalls\n"
	"   ./syscall -a alert -p PID    # trace syscall PID and alert\n"
	"   ./syscall -c CG     # Trace syscall under cgroupsPath CG\n";

static const struct argp_option opts[] = {
	{"action", 'a', "ACTION", 0, "do this action when bad things happen"},
	{"pid", 'p', "PID", 0, "trace process PID and its all child processes"},
	{"verbose", 'v', NULL, 0, "Verbose debug output"},
	{"cgroup", 'c', "/sys/fs/cgroup/unified", 0, "Trace syscall in cgroup path"},
	{NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
	{},
};


static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	int pid;

	switch (key)
	{
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'a':
		if(strcmp(arg, "alert") == 0) {
			syscall_env.intercept = false;
		} else if(strcmp(arg, "intercept") == 0) {
			syscall_env.intercept = true;
		} else {
			printf("Parama error: -a should be alter/intercept!\n");
			return ARGP_ERR_UNKNOWN;
		}
		break;
	case 'p':
		errno = 0;
		pid = atoi(arg);
		if (errno || pid < 0 || pid >= INT_MAX)
		{
			fprintf(stderr, "Invalid PID %s\n", arg);
			argp_usage(state);
		}
		syscall_env.targ_pid = (int)pid;
		break;
	case 'v':
		syscall_env.verbose = true;
		break;
	case 'c':
		syscall_env.cgroupspath = arg;
		syscall_env.filter_cg = true;
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}


static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !syscall_env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static void handle_event(void *ctx, int cpu, void *data, __u32 data_sz)
{
	const struct syscall_event *e = data;
	struct tm *tm;
	char ts[32];
	char syscall_name_buf[32];
	time_t t;
	FILE *fp;
	fp = fopen("log/sysrecord.log", "a");

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	syscall_name(e->syscall_id, syscall_name_buf, sizeof(syscall_name_buf));
	if(e->occur_times >= syscall_env.filter_report_times) {
		fprintf(fp, "[ERROR] Frequent syscall: %s over %d times\n", syscall_name_buf, syscall_env.filter_report_times);
	}
	
	fprintf(fp, "%-8s %-16s %-7d %-7d [%lu] %-10u %-15s %-11d\n", ts, e->comm, e->pid, e->ppid, e->mntns, e->syscall_id, syscall_name_buf, e->occur_times);
	fclose(fp);
	return;
}

void handle_lost_events(void *ctx, int cpu, __u64 lost_cnt)
{
	fprintf(stderr, "Lost %llu events on CPU #%d!\n", lost_cnt, cpu);
}

int main(int argc, char **argv)
{
	// struct ring_buffer *rb = NULL;
	struct perf_buffer *pb = NULL;
	struct sysrecord_bpf *skel;
	int err;
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};

	err = argp_parse(&argp, argc, argv, 0, 0, 0);
	if (err)
	{
		return -1;
	}
	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	// 创建log文件夹
	system("mkdir -p log");

	FILE *fp;
	fp = fopen("log/sysrecord.log", "a");
	/* syscall events */
	fprintf(fp, "%-8s %-16s %-7s %-7s %-12s %-10s %-15s %-11s\n", "TIME", "COMM", "PID", "PPID", "MNT_NS", "SYSCALL_ID", "SYSCALL_NAME", "OCCUR_TIMES");
	fclose(fp);

	syscall_env.exiting = &exiting;

	if (!syscall_env.exiting)
	{
		fprintf(stderr, "syscall_env.exiting is not set.\n");
		return -1;
	}

	/* Parse command line arguments */
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Load and verify BPF application */
	skel = sysrecord_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	/* 通过pid获取ppid */ 
	char cmd[128];
	char result[16];
	sprintf(cmd, "ps -elf |awk '$4=='%d'{print $5}'", syscall_env.targ_pid);
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

	skel->rodata->targ_pid = syscall_env.targ_pid;
	skel->rodata->targ_ppid = ppid;
	skel->rodata->filter_cg = syscall_env.filter_cg;
	skel->rodata->filter_report_times = syscall_env.filter_report_times;
	skel->rodata->min_duration_ns = syscall_env.min_duration_ms * 1000;
	skel->rodata->intercept = syscall_env.intercept;
	init_syscall_names();

	/* update cgroup path fd to map */
	if (syscall_env.filter_cg)
	{
		int idx, cg_map_fd;
		int cgfd = -1;
		idx = 0;
		cg_map_fd = bpf_map__fd(skel->maps.cgroup_map);
		cgfd = open(syscall_env.cgroupspath, O_RDONLY);
		if (cgfd < 0)
		{
			fprintf(stderr, "Failed opening Cgroup path: %s", syscall_env.cgroupspath);
			goto cleanup;
		}
		if (bpf_map_update_elem(cg_map_fd, &idx, &cgfd, BPF_ANY))
		{
			fprintf(stderr, "Failed adding target cgroup to map");
			goto cleanup;
		}
	}

	/* Load & verify BPF programs */
	err = sysrecord_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = sysrecord_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* setup event callbacks */
	pb = perf_buffer__new(bpf_map__fd(skel->maps.syscall_event_pb), PERF_BUFFER_PAGES,
						  handle_event, handle_lost_events, NULL, NULL);
	if (!pb)
	{
		err = -errno;
		fprintf(stderr, "failed to open perf buffer: %d\n", err);
		goto cleanup;
	}
	/* main: poll */
	while (!*syscall_env.exiting)
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
	/* Clean up */
	perf_buffer__free(pb);
	sysrecord_bpf__destroy(skel);
	free_syscall_names();

	return err < 0 ? -err : 0;
}