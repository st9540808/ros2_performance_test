#!/usr/bin/python
#
# This is a Hello World example that uses BPF_PERF_OUTPUT.

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import json
import sofa_time

# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u64 ts;
    u64 lat;
    char comm[TASK_COMM_LEN];
    char func[20];
};
BPF_PERF_OUTPUT(events);
BPF_ARRAY(start_time, struct data_t, 1);

int publish_probe(struct pt_regs *ctx) {
    struct data_t data = {};    
    
    data.ts = bpf_ktime_get_ns();
    strcpy(data.func, "publish");
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    start_time.update(&(int){0}, &data);
    return 0;
}
int subscription_probe(struct pt_regs *ctx) {
    struct data_t *prev;
    u64 curr;

    curr = bpf_ktime_get_ns();
    prev = start_time.lookup(&(int){0});
    if (prev) {
        prev->lat = curr - prev->ts;
        events.perf_submit(ctx, prev, sizeof(struct data_t));
    }
    return 0;
}
"""

# load BPF program
b = BPF(text=prog)
b.attach_uprobe(name="./install/ros_course_demo/lib/ros_course_demo/talker",
                sym="_ZN6rclcpp9PublisherIN8std_msgs3msg7String_ISaIvEEES4_E7publishERKS5_",
                fn_name="publish_probe")
b.attach_uprobe(name="./install/ros_course_demo/lib/ros_course_demo/listener",
                sym="_ZN8Listener8callbackESt10shared_ptrIN8std_msgs3msg7String_ISaIvEEEE",
                fn_name="subscription_probe")

# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

data_list = []
# process event
def print_event(cpu, data, size):
    global data_list
    event = b["events"].event(data)
    data_keys = ['ts', 'lat', 'comm', 'func']
    d = {field:getattr(event, field) for field in data_keys} # a data point in sofa
    d['ts'] = d['ts'] / 1e9
    d['lat'] = d['lat'] / 1e6
    data_list.append(d)
    print(d['ts'])


# loop with callback to print_event
b["events"].open_perf_buffer(print_event)
while 1:
    try:
        b.perf_buffer_poll()
    except KeyboardInterrupt:
        break


with open('./sofalog/sofa_time.txt') as f:
    lines = f.readlines()
    sofa_start = float(lines[0])
off = sofa_time.get_unix_mono_diff()

print(off)
print(sofa_start)

for data in data_list:
    data['x'] = data.pop('ts') + off - sofa_start
    data['y'] = data.pop('lat')
    data['name'] = 'rclcpp::Node::publish()'
output = {"name": "transmission latency", "color": "DeepPink"}
output['data'] = data_list
print('')
print('transmission_latency =', json.dumps(output))