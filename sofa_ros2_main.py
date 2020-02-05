#!/usr/bin/python3

import multiprocessing
import time
import sys
import os
import ebpf_ros2_trace_send
import ebpf_ros2_trace_recv
import ebpf_ros2_trace_tc_act

sys.path.insert(0, '/home/st9540808/Desktop/VS_Code/sofa/bin')
import sofa_print

perf_procs = [ebpf_ros2_trace_tc_act.trace_tc_act(),
              ebpf_ros2_trace_send.trace_send(),
              ebpf_ros2_trace_recv.trace_recv()]

def run():
    sofa_print.print_main_progress('Starting ebpf programs for ros2')

    for proc in perf_procs:
        proc.start()

    while True:
        try:
            for proc in perf_procs:
                proc.join()
        except KeyboardInterrupt as e:
            pass
        if not all(proc.is_alive() for proc in perf_procs):
            break

if __name__ == "__main__":
    run()