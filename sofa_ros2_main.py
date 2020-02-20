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

# all processes will be interrupt when enter a Ctrl-C to sofa_ros2_main.py
class trace_main:
    end = multiprocessing.Event()
    perf_procs = [ebpf_ros2_trace_tc_act.trace_tc_act(args=(end,)),
                  ebpf_ros2_trace_send.trace_send(args=(end,)),
                  ebpf_ros2_trace_recv.trace_recv(args=(end,))]

    def run(self):
        sofa_print.print_main_progress('Starting ebpf programs for ros2')

        for proc in self.perf_procs:
            sofa_print.print_main_progress('Starting %s' % type(proc).__name__)
            proc.start()

        while True:
            try:
                for proc in self.perf_procs:
                    proc.join()
            except KeyboardInterrupt as e:
                pass
            if not all(proc.is_alive() for proc in self.perf_procs):
                break

    def start(self):
        sofa_print.print_main_progress('Starting ebpf programs for ros2')

        for proc in self.perf_procs:
            sofa_print.print_main_progress('Starting %s' % type(proc).__name__)
            proc.start()

    def terminate(self):
        self.end.set()
        while any(proc.is_alive() for proc in self.perf_procs):
            try:
                for proc in self.perf_procs:
                    proc.join()
            except KeyboardInterrupt as e:
                pass

if __name__ == "__main__":
    main = trace_main()
    main.start()
    while True:
        try:
            time.sleep(0.1)
        except KeyboardInterrupt as e:
            break
    main.terminate()