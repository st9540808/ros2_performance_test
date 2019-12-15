#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import threading
import sofa_time
import statistics
#import pandas as pd
import time

time_offset_table = []
class time_offset_from(threading.Thread):
    def __init__(self, serv_addr):
        threading.Thread.__init__(self)
        self.serv_addr = serv_addr
        self.stopped = threading.Event()
        self.start()
    def run(self):
        global time_offset_table
        while not self.stopped.wait(1):
            ts = sofa_time.get_monotonic_time()
            off = sofa_time.get_time_offset_from(self.serv_addr)
            time_offset_table.append([ts, off])
            print('%.5f  %.5f' % (ts, off))
    def stop(self):
        self.stopped.set()


t = time_offset_from('192.168.3.10')
while 1:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        t.stop()
        print('exit')
        print(time_offset_table)
        exit(0)

# define BPF program
prog = """
#include <linux/sched.h>

// define output data structure in C
struct data_t {
    u64 ts;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(events);

int subscription_probe(struct pt_regs *ctx) {
    struct data_t data;
    u64 curr;

    data.ts = bpf_ktime_get_ns()*1e3;
    events.perf_submit(ctx, prev, sizeof(struct data_t));
    return 0;
}
"""

b = BPF(text=prog)
b.attach_uprobe(name="./install/ros_course_demo/lib/ros_course_demo/listener",
                sym="_ZN8Listener8callbackESt10shared_ptrIN8std_msgs3msg7String_ISaIvEEEE",
                fn_name="subscription_probe")

