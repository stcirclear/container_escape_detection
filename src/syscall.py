from pylcc.lbcBase import ClbcBase, CeventThread
from syscallTable import *
import argparse
import sys


bpfProg = r"""
#include "lbc.h"
#define TASK_COMM_LEN 16

struct event_t {
    u32 host_pid;
    u32 host_ppid;
    char comm[TASK_COMM_LEN];
    long syscall_id;
};

LBC_PERF_OUTPUT(e_out, struct event_t, 128);
SEC("raw_tracepoint/sys_enter")
int tp_raw_syscall_sys_enter(struct bpf_raw_tracepoint_args *ctx){
    struct event_t event = {};
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    
    event.host_pid = bpf_get_current_pid_tgid() >> 32;
    event.host_ppid = BPF_CORE_READ(task, real_parent, tgid);
    
    bpf_get_current_comm(&event.comm, TASK_COMM_LEN);
    long syscall_id = ctx->args[1];
    event.syscall_id = syscall_id;
    bpf_perf_event_output(ctx, &e_out, BPF_F_CURRENT_CPU, &event, sizeof(event));
    return 0;
}

char _license[] SEC("license") = "GPL";
"""


class CtraceSysEnter(ClbcBase):
    def __init__(self):
        super(CtraceSysEnter, self).__init__("syscall", bpf_str=bpfProg)

    def _cb(self, cpu, e):
        # monitor parent process and it's child processes
        if len(pid_set) == 0 or e.host_ppid in pid_set:
            pid_set.add(e.host_pid)
            cal_syscall_count(e.syscall_id)
            print("cpu:%d\thost pid:%d\thost ppid:%d\tcomm:%s\tsyscall id:%ld\tsyscall name:%s\tsyscall count:%d" % (
                cpu, e.host_pid, e.host_ppid, e.comm, e.syscall_id, get_syscall_name(e.syscall_id), get_syscall_count()[e.syscall_id]
            ))

    def loop(self):
        CeventThread(self, 'e_out', self._cb)
        self.waitInterrupt()


def get_options(args=sys.argv[1:]):
    parser = argparse.ArgumentParser(description="Parses command.")
    parser.add_argument("-pp", "--ppid", default=-1, type=int, help="Parent process id.")
    options = parser.parse_args(args)
    return options


if __name__ == "__main__":
    options = get_options()
    pid_set = set()
    if options.ppid != -1:
        pid_set.add(options.ppid)
    e = CtraceSysEnter()
    e.loop()
