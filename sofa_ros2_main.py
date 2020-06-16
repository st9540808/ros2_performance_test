#!/usr/bin/python3

import multiprocessing
import time
import sys
import os
import ebpf_ros2_trace_send
import ebpf_ros2_trace_recv
import ebpf_ros2_trace_tc_act
from bcc import BPF

# sys.path.insert(0, '/home/st9540808/Desktop/sofa/bin')
import sofa_print
import sofa_config

# all processes will be interrupt when enter a Ctrl-C to sofa_ros2_main.py
class trace_main:
    def __init__(self, cfg=None):
        if cfg is not None:
            if cfg.ros2_topic_whitelist:
                sofa_print.print_hint("enable ros2 topic whitelist")
            # Not implemented yet
            if cfg.ros2_topic_blacklist:
                sofa_print.print_hint("enable ros2 topic blacklist")
        else:
            cfg = sofa_config.SOFA_Config()

        cflags = []
        if cfg.ros2_topic_whitelist:
            cflags.append('-DWHITELIST=1')
        b = BPF(src_file='./ebpf_ros2.c', cflags=cflags)

        os.makedirs(os.path.join(cfg.logdir, cfg.ros2logdir), exist_ok=True)

        self.end = multiprocessing.Event()
        self.ready = multiprocessing.Event()
        arg = {'set': self.end, 'config': cfg, 'b': b}
        self.perf_procs = [ebpf_ros2_trace_tc_act.trace_tc_act(args=(arg)),
                           ebpf_ros2_trace_send.trace_send(args=(arg)),
                           ebpf_ros2_trace_recv.trace_recv(args=(arg))]

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
        # TODO: Use a process synchronization to eliminate race condition for
        #       eBPF attach_probe and profiled program
        time.sleep(1.5)

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