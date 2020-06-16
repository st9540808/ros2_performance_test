#!/usr/bin/python3

from bcc import BPF
import pyroute2
import time
import sys
import os
import multiprocessing
import sofa_ros2_utilities
from sofa_ros2_utilities import perf_callback_factory

# sys.path.insert(0, '/home/st9540808/Desktop/sofa/bin')
import sofa_config

# device = sys.argv[1]
#mode = BPF.XDP
device = 'enx00e04c68006a'
device = 'enp0s25'
device = 'lo'
mode = BPF.SCHED_CLS

class trace_tc_act(multiprocessing.Process):
    # define callback function for perf events
    @perf_callback_factory('cls_ingress', ['ts', 'magic', 'guid', 'seqnum', 'msg_id', 'saddr', 'sport', 'daddr', 'dport'])
    def print_cls_ingress(self, *args):
        d = args[0]
        d['msg_id'] = {0x15: 'DATA', 0x16: 'DATAFRAG'}[d['msg_id']]

    @perf_callback_factory('cls_egress', ['ts', 'magic', 'guid', 'seqnum', 'msg_id', 'saddr', 'sport', 'daddr', 'dport'])
    def print_cls_egress(self, *args):
        d = args[0]
        d['msg_id'] = {0x15: 'DATA', 0x16: 'DATAFRAG'}[d['msg_id']]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        arg = kwargs['args']
        self.set = arg['set']
        self.cfg = arg['config']

        # load BPF program
        self.b = arg['b']

    def run(self):
        if not self.is_alive():
            print("Printing, hit CTRL+C to stop")

        # use print_raw if executed as a child
        fields = ['layer', 'ts', 'guid', 'seqnum', 'msg_id', 'saddr', 'sport', 'daddr', 'dport']
        fmtstr = '{:<20} {:<13.5f} {:<40} {:<7d} {:<10} {:<#12x} {:<#12x} {:<#12x} {:<#12x}'
        self.log = sofa_ros2_utilities.Log(fields=fields, fmtstr=fmtstr,
                                           cvsfilename=os.path.join(self.cfg.logdir, self.cfg.ros2logdir, 'cls_bpf_log.csv'),
                                           print_raw=self.is_alive())

        b = self.b
        fn_egress = b.load_func("cls_ros2_egress_prog", mode)
        fn_ingress = b.load_func("cls_ros2_ingress_prog", mode)

        ip = pyroute2.IPRoute()
        ipdb = pyroute2.IPDB(nl=ip)
        idx = ipdb.interfaces[device].index
        ip.tc("add", "clsact", idx)
        # add egress clsact
        ip.tc("add-filter", "bpf", idx, ":1", fd=fn_egress.fd, name=fn_egress.name,
              parent="ffff:fff3", classid=1, direct_action=True)
        # add ingress clsact
        ip.tc("add-filter", "bpf", idx, ":1", fd=fn_ingress.fd, name=fn_ingress.name,
              parent="ffff:fff2", classid=1, direct_action=True)

        b["cls_egress"].open_perf_buffer(self.print_cls_egress)
        b["cls_ingress"].open_perf_buffer(self.print_cls_ingress)
        while not self.set.is_set():
            try:
                b.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                print('')
                break
        print("[trace_tc_act] Removing filter from device")
        self.log.close()

        ip.tc("del", "clsact", idx)
        ipdb.release()

if __name__ == "__main__":
    cfg = sofa_config.SOFA_Config()

    cflags = []
    if cfg.ros2_topic_whitelist:
        cflags.append('-DWHITELIST=1')
    b = BPF(src_file='./ebpf_ros2.c', cflags=cflags)

    trace = trace_tc_act(args=({'set': multiprocessing.Event(), 'config': cfg, 'b': b}))
    trace.run()