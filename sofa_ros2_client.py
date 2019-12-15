#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import threading
import sofa_time
import statistics
#import pandas as pd
import time, sys
import math

serv_addr = '192.168.3.10'
if len(sys.argv) > 1:
    serv_addr = sys.argv[1]
    print(sys.argv[1])

time_offset_table = []
time_offset_median = []
class time_offset_from(threading.Thread):
    def __init__(self, serv_addr):
        threading.Thread.__init__(self)
        self.serv_addr = serv_addr
        self.stopped = threading.Event()
        self.start()
    def run(self):
        global time_offset_table
        while not self.stopped.wait(0.4):
            ts = time.time()
            off = sofa_time.get_time_offset_from(self.serv_addr)
            time_offset_table.append([ts, off])
            print('%.5f  %.5f' % (ts, off))
    def stop(self):
        self.stopped.set()


t = time_offset_from(serv_addr)
while 1:
    try:
        time.sleep(1)
    except KeyboardInterrupt:
        t.stop()
        n = math.ceil(len(time_offset_table) / 30) * 30
        n_iter = math.ceil(len(time_offset_table) / 30)

        # pad time_offset_table
        last = time_offset_table[-1]
        time_offset_table += [last] * (n-len(time_offset_table))

        for i in range(n_iter):
            print(i)
            data_list = [x[1] for x in time_offset_table[i*30:(i+1)*30]]
            median = statistics.median(data_list)
            time_offset_median.append([[time_offset_table[i][0], time_offset_table[(i+1)*30-1][0]], median])

        print(time_offset_median)
        print('exit')
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

