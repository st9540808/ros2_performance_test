#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import os
import multiprocessing
import json
import sofa_time
import sofa_ros2_utilities
from sofa_ros2_utilities import perf_callback_factory

class trace_recv(multiprocessing.Process):
    @perf_callback_factory(event_name='recv_rmw',
                           data_keys=['ts', 'implementation', 'func', 'comm', 'topic_name', 'subscriber', 'pid', 'guid'])
    def print_rmw(self, *args):
        d = args[0]
        d['layer'] = 'rmw'

    @perf_callback_factory(event_name='recv_fastrtps',
                           data_keys=['func', 'ts', 'comm', 'pid', 'subscriber', 'guid', 'seqnum', 'saddr', 'sport', 'daddr', 'dport'])
    def print_fastrtps(self, *args):
        d = args[0]
        if d['seqnum'] == 0:
            d.pop('seqnum')
        d['layer'] = 'fastrtps'

    @perf_callback_factory(event_name='recv_cyclonedds',
                           data_keys=['func', 'ts', 'comm', 'pid', 'subscriber', 'guid', 'seqnum', 'saddr', 'sport', 'daddr', 'dport'])
    def print_cyclonedds(self, *args):
        d = args[0]
        if d['seqnum'] == 0:
            d.pop('seqnum')
        d['layer'] = 'cyclonedds'

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        arg = kwargs['args']
        self.set = arg['set']
        self.config = arg['config']

        # attach eBPF programs to probes
        self.b = b = arg['b']
        b.attach_uretprobe(name="/opt/ros/dashing/lib/librmw_implementation.so",
                           sym="rmw_wait",
                           fn_name="rmw_wait_retprobe")
        b.attach_uretprobe(name="/opt/ros/dashing/lib/librmw_implementation.so",
                           sym="rmw_take_with_info",
                           fn_name="rmw_take_with_info_retprobe")
        b.attach_uprobe(name="/opt/ros/dashing/lib/librmw_implementation.so",
                        sym="rmw_take_with_info",
                        fn_name="rmw_take_with_info_probe")
        b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libfastrtps.so'),
                        sym="_ZN8eprosima8fastrtps17SubscriberHistory19add_received_changeEPNS0_4rtps13CacheChange_tE",
                        fn_name="add_received_change_probe")
        b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libfastrtps.so'),
                        sym="_ZN8eprosima8fastrtps4rtps18UDPChannelResource7ReceiveEPhjRjRNS1_9Locator_tE",
                        fn_name="fastrtps_UDPChannelResource_Receive_probe")
        b.attach_uretprobe(name=os.path.realpath('/opt/ros/dashing/lib/libfastrtps.so'),
                           sym="_ZN8eprosima8fastrtps4rtps18UDPChannelResource7ReceiveEPhjRjRNS1_9Locator_tE",
                           fn_name="fastrtps_UDPChannelResource_Receive_retprobe")
        b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libfastrtps.so'),
                        sym="_ZN8eprosima8fastrtps4rtps16ReceiverResource14OnDataReceivedEPKhjRKNS1_9Locator_tES7_",
                        fn_name="fastrtps_ReceiverResource_OnDataReceived_probe")
        # b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libfastrtps.so'),
        #                 sym="_ZN8eprosima8fastrtps4rtps18UDPChannelResource24perform_listen_operationENS1_9Locator_tE",
        #                 fn_name="fastrtps_UDPChannelResource_perform_listen_operation")

        b.attach_uretprobe(name=os.path.realpath('/opt/ros/dashing/lib/libddsc.so'),
                        sym="ddsrt_recvmsg",
                        fn_name="cyclone_ddsrt_recvmsg_retprobe")
        b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libddsc.so'),
                        sym="ddsi_udp_conn_read",
                        fn_name="cyclone_ddsi_udp_conn_read_probe")
        b.attach_uretprobe(name=os.path.realpath('/opt/ros/dashing/lib/libddsc.so'),
                           sym="ddsi_udp_conn_read",
                           fn_name="cyclone_ddsi_udp_conn_read_retprobe")
        # b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libddsc.so'),
        #                 sym="handle_regular",
        #                 fn_name="cyclone_handle_regular_probe")
        b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libddsc.so'),
                        sym="deliver_user_data",
                        fn_name="cyclone_deliver_user_data_probe")

    def run(self):
        # activate logging system
        fields = ['layer', 'ts', 'implementation', 'func', 'comm', 'topic_name', 'pid', 'subscriber', 'guid', 'seqnum', 'saddr', 'sport', 'daddr', 'dport']
        fmtstr = '{:<10} {:<14.4f} {:<24} {:<28} {:<11} {:<22} {:<8} {:<#18x} {:<40} {:<3d} {:<#12x} {:<#12x} {:<#12x} {:<#12x}'
        self.log = sofa_ros2_utilities.Log(fields=fields, fmtstr=fmtstr,
                                           cvsfilename='recv_log.csv', print_raw=self.is_alive())

        # loop with callback to print_event
        b = self.b
        b["recv_rmw"].open_perf_buffer(self.print_rmw)
        b["recv_fastrtps"].open_perf_buffer(self.print_fastrtps)
        b["recv_cyclonedds"].open_perf_buffer(self.print_cyclonedds)
        while not self.set.is_set():
            try:
                b.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
        self.log.close()
        print("[trace_recv] Exit")

if __name__ == "__main__":
    config = {'whitelist': False, 'blacklist': False}

    cflags = []
    if config['whitelist']:
        cflags.append('-DWHITELIST=1')
    b = BPF(src_file='./ebpf_ros2.c', cflags=cflags)

    trace = trace_recv(args=({'set': multiprocessing.Event(), 'config': config, 'b': b}))
    trace.run()