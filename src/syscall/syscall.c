#include "syscall_helpers.h"
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

#include "syscall.h"
#include "syscall.skel.h"

struct syscall_env
{
  bool verbose;
  volatile bool *exiting;

  char *cgroupspath;
  // file cgroup
  bool filter_cg;
  pid_t target_pid;
  // the min sample duration in ms
  long min_duration_ms;
  // the times syscall a process is sampled
  unsigned char filter_report_times;
};


static struct syscall_env syscall_env = {0};

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

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct syscall_event *e = data;
    struct tm *tm;
    char ts[32];
    char syscall_name_buf[32];
    time_t t;

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    syscall_name(e->syscall_id, syscall_name_buf, sizeof(syscall_name_buf));
    printf("%-8s %-16s %-7d %-7d [%lu] %u\t%s\t%d\n",
           ts, e->comm, e->pid, e->ppid, e->mntns, e->syscall_id, syscall_name_buf, e->occur_times);

    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct syscall_bpf *skel;
    int err;

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Process events */
    printf("%-8s %-5s %-16s %-7s %-7s %s\n",
           "TIME", "EVENT", "COMM", "PID", "PPID", "SYSCALL_ID");

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
    skel = syscall_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open and load BPF skeleton\n");
        return 1;
    }

    skel->rodata->filter_pid = syscall_env.target_pid;
    skel->rodata->filter_cg = syscall_env.filter_cg;
    /* Parameterize BPF code with minimum duration parameter */
    skel->rodata->min_duration_ns = syscall_env.min_duration_ms * 1000000ULL;
    if (syscall_env.filter_report_times > 200)
    {
        fprintf(stderr, "filter_report_times to large\n");
        return 1;
    }
    skel->rodata->filter_report_times = syscall_env.filter_report_times;

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
    err = syscall_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoints */
    err = syscall_bpf__attach(skel);
    if (err)
    {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.event_map), handle_event, NULL, NULL);
    if (!rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    while (!*syscall_env.exiting)
    {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR)
        {
            err = 0;
            break;
        }
        if (err < 0)
        {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    /* Clean up */
    ring_buffer__free(rb);
    syscall_bpf__destroy(skel);
	free_syscall_names();
    

    return err < 0 ? -err : 0;
}
