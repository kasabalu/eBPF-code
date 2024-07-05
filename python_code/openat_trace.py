#!/usr/bin/python3
# This script traces openat syscall and prints pid of process that called openat syscall
# tail -f /sys/kernel/debug/tracing/trace_pipe or cat to see the output of this script
from bcc import BPF
from time import sleep

bpf_text = '''
#include <uapi/linux/ptrace.h>
#include <linux/fs.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    char comm[TASK_COMM_LEN];
};


struct syscall_openat_args {
// see /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat
// thow away the first lines using unused variable( thowaway variable that starts with _)
    uint64_t  _unused;
    u32 __syscall_nr;
    u64 dfd;
    char *filename;
    u64 flags;
    u64 mode;

};
// functon for openat syscall
int sys_enter_openat_fn(struct syscall_openat_args *args) {

    // https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md
    // since we need to get pid of process, we need to use bpf_get_current_pid_tgid() function based on above documentation.
    // Returns the process ID in the lower 32 bits (kernel's view of the PID, which in user space is usually presented as the thread ID),
    // and the thread group ID in the upper 32 bits
    // (what user space often thinks of as the PID). By directly setting this to a u32, we discard the upper 32 bits.
    // get pid of process. get rid of upper 32 bits using shift operator
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_trace_printk("openat syscal called pid: %d \\n", pid);
    return 0;

};
'''
bpf = BPF(text=bpf_text) # inject code into kernel
# attach to sys_enter_openat function
bpf.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="sys_enter_openat_fn")

sleep(60)
