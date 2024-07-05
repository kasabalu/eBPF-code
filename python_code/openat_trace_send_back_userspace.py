#!/usr/bin/python
# This script traces openat syscall and prints pid of process that called openat syscall and filename that was opened
# and sends this information back to userspace using ring buffer
from bcc import BPF

# we want grab information from kernel and send it back to userspace.
# we use ring buffer to send data back to userspace.
# we need to use bpf_trace_printk() function to send it back to userspace.

bpf_text = '''
#include <linux/sched.h>

BPF_PERF_OUTPUT(events); // ring buffer to send data back to userspace

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
    struct data_t data = {};
    u32 pid = (u32)(bpf_get_current_pid_tgid() >> 32);
    bpf_trace_printk("openat syscal called pid: %d \\n", pid);

    data.pid = pid;
    //bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_str(data.comm, TASK_COMM_LEN, args->filename); // get comm from args

    events.perf_submit(args, &data, sizeof(data)); // send data back to userspace, in place of args, we can send any data as context
                                                // we want to send back to userspace

    return 0;

};
'''
bpf = BPF(text=bpf_text) # inject code into kernel
# attach to sys_enter_openat function
bpf.attach_tracepoint(tp="syscalls:sys_enter_openat", fn_name="sys_enter_openat_fn")

def func_sys_enter_openat(cpu, data, size):
    # receive data from kernel, perf_submit() function. data is in form of dictionary
    event = bpf["events"].event(data)
    print("event is: {}".format(type(event)))  # <class 'bcc.table'>
    print("pid is: ", event.pid, "comm is: ", event.comm.decode('utf-8'))


# loop with callback to print_event
bpf["events"].open_perf_buffer(func_sys_enter_openat)

while True:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
