#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import json
import sofa_time
import time

# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int publish_probe(struct pt_regs *ctx) {
    struct data_t data = {};

    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    events.perf_submit(ctx, &data, sizeof(struct data_t));
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_uprobe(name="./install/ros_course_demo/lib/ros_course_demo/talker",
                sym="_ZN6rclcpp9PublisherIN8std_msgs3msg7String_ISaIvEEES4_E7publishERKS5_",
                fn_name="publish_probe")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

unix_mono_diff = sofa_time.get_unix_mono_diff()
ebpf_data = []
# process event
def print_event(cpu, data, size):
    global ebpf_data
    event = b["events"].event(data)
    data_keys = ['ts', 'comm']
    d = {field:getattr(event, field) for field in data_keys} # a data point in sofa
    d['ts'] = d['ts'] / 1e9 + sofa_time.get_unix_mono_diff()
    ebpf_data.append(d['ts'])
    print(d['ts'])


# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break

with open('./talker_ebpf.data', 'w') as f:
    for data in ebpf_data:
        offset = 0
        f.write(str(data - offset) + '\n')