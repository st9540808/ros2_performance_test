#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from time import sleep

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u64 ts;
    u32 tid;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int test_probe(struct pt_regs *ctx) {
    struct data_t data = {};

    data.ts = bpf_ktime_get_ns();
    data.tid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(struct data_t));
    return 0;
}
""")

b.attach_uprobe(name="/home/st9540808/Desktop/VS_Code/ros2-build_from_source/build/rmw_fastrtps_cpp/librmw_fastrtps_cpp.so",
                sym="rmw_serialize",
                fn_name="test_probe")


data_keys = ['ts', 'comm', 'pid']

def print_event(cpu, data, size):
    event = b["events"].event(data)
    d = {field:getattr(event, field) for field in data_keys} # a data point in sofa

    d['ts'] = d['ts'] / 1e9
    for k, v in d.items():
        if type(v) == bytes:
            d[k] = d[k].decode('utf-8')
    print('{:<18.5f} {:<10} {:<8} {:<22} {:<22} {:<#18x} {:<#18x}'.format(*list(d.values())))

# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break