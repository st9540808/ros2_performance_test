#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import os
import multiprocessing
import ctypes
import json
import sofa_time
import sofa_ros2_utilities
from sofa_ros2_utilities import perf_callback_factory

topic = ctypes.c_byte * 40
class Key(ctypes.Structure):
    _fields_ = [
        ('prefixlen', ctypes.c_uint32),
        ('topic_name', topic),
    ]

class trace_send(multiprocessing.Process):
    @perf_callback_factory(event_name='send_rcl',
                           data_keys=['ts', 'implementation', 'comm', 'pid', 'topic_name', 'mp_writer', 'rmw_guid'],
                           remap={'mp_writer':'publisher', 'rmw_guid':'guid'})
    def print_rcl(self, *args):
        d = args[0]
        d['func'] = 'rcl_publish'
        d['layer'] = 'rcl'

    @perf_callback_factory(event_name='send_fastrtps',
                           data_keys=['func', 'ts', 'comm', 'pid', 'endpoint', 'ep_guid', 'seqnum', 'daddr', 'dport'],
                           remap={'endpoint':'publisher', 'ep_guid':'guid'})
    def print_fastrtps(self, *args):
        d = args[0]
        if d['seqnum'] == 0:
            d.pop('seqnum')
        d['layer'] = 'fastrtps'

    @perf_callback_factory(event_name='send_cyclonedds',
                           data_keys=['func', 'ts', 'comm', 'pid', 'publisher', 'guid', 'seqnum'])
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
        b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/librcl.so'),
                        sym="rcl_publish",
                        fn_name="rcl_publish_probe")
        # fastrtps
        b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libfastrtps.so'),
                        sym="_ZN8eprosima8fastrtps16PublisherHistory14add_pub_changeEPNS0_4rtps13CacheChange_tERNS2_11WriteParamsERSt11unique_lockISt21recursive_timed_mutexENSt6chrono10time_pointINSB_3_V212steady_clockENSB_8durationIlSt5ratioILl1ELl1000000000EEEEEE",
                        fn_name="fastrtps_add_pub_change_probe")
        b.attach_uretprobe(name=os.path.realpath('/opt/ros/dashing/lib/libfastrtps.so'),
                           sym="_ZN8eprosima8fastrtps16PublisherHistory14add_pub_changeEPNS0_4rtps13CacheChange_tERNS2_11WriteParamsERSt11unique_lockISt21recursive_timed_mutexENSt6chrono10time_pointINSB_3_V212steady_clockENSB_8durationIlSt5ratioILl1ELl1000000000EEEEEE",
                           fn_name="fastrtps_add_pub_change_retprobe")
        b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libfastrtps.so'),
                        sym="_ZN8eprosima8fastrtps4rtps16RTPSMessageGroupD1Ev",
                        fn_name="fastrtps_RTPSMessageGroup_destructor_probe")
        b.attach_uretprobe(name=os.path.realpath('/opt/ros/dashing/lib/libfastrtps.so'),
                           sym="_ZN8eprosima8fastrtps4rtps16RTPSMessageGroupD1Ev",
                           fn_name="fastrtps_RTPSMessageGroup_destructor_retprobe")
        b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libfastrtps.so'),
                        sym="_ZN8eprosima8fastrtps4rtps19RTPSParticipantImpl8sendSyncEPNS1_12CDRMessage_tEPNS1_8EndpointERKNS1_9Locator_tERNSt6chrono10time_pointINSA_3_V212steady_clockENSA_8durationIlSt5ratioILl1ELl1000000000EEEEEE",
                        fn_name="fastrtps_RTPSParticipantImpl_sendSync_probe")
        # b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libfastrtps.so'),
        #                 sym="_ZN8eprosima8fastrtps4rtps21UDPTransportInterface4sendEPKhjRN4asio21basic_datagram_socketINS5_2ip3udpENS5_23datagram_socket_serviceIS8_EEEERKNS1_9Locator_tEb",
        #                 fn_name="fastrtps_UDPTransportInterface_send_probe")
        # b.attach_uprobe(name="/home/st9540808/Desktop/VS_Code/ros2-build_from_source/install/fastrtps/lib/libfastrtps.so.1.8.2",
        #                 sym="_ZN8eprosima8fastrtps4rtps16RTPSMessageGroup4sendEv",
        #                 fn_name="fastrtps_send_probe")
        # b.attach_uprobe(name="/home/st9540808/Desktop/VS_Code/ros2-build_from_source/install/fastrtps/lib/libfastrtps.so.1.8.2",
        #                 sym="_ZN8eprosima8fastrtps4rtps16RTPSMessageGroup8add_dataERKNS1_13CacheChange_tERKSt6vectorINS1_6GUID_tESaIS7_EERKNS1_13LocatorList_tEb",
        #                 fn_name="fastrtps_add_data_probe")

        # cyclone dds
        b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libddsc.so'),
                        sym="dds_write_impl",
                        fn_name="cyclone_dds_write_impl_probe")
        b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libddsc.so'),
                        sym="whc_default_insert_seq",
                        fn_name="cyclone_whc_default_insert_seq")
        b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libddsc.so'),
                        sym="nn_xpack_send1",
                        fn_name="cyclone_nn_xpack_send1")
        # b.attach_uprobe(name=os.path.realpath('/opt/ros/dashing/lib/libddsc.so'),
        #                 sym="write_sample_gc",
        #                 fn_name="cyclone_write_sample_gc")

        # topic filter (whitelist)
        if self.config['whitelist'] and os.path.exists('whitelist.txt'):
            with open('whitelist.txt') as f:
                whitelist = b["whitelist"]
                lines = filter(lambda x: len(x) >= 1, f.read().splitlines())
                for line in lines:
                    topic_bytes = line[:40].encode('ascii') + b'\0'
                    # print(len(topic_bytes) * 8)
                    key = Key(prefixlen=len(topic_bytes) * 8, topic_name=topic(*topic_bytes))
                    whitelist[key] = ctypes.c_uint8(0)

    def run(self):
        # activate logging system
        fmtstr = '{:<10} {:<13.5f} {:<20} {:<28} {:<16} {:<8} {:<22} {:<#18x} {:<44} {:<6d} {:<#12x} {:<#12x}'
        fields = ['layer', 'ts', 'implementation', 'func', 'comm', 'pid', 'topic_name', 'publisher', 'guid', 'seqnum', 'daddr', 'dport']
        self.log = sofa_ros2_utilities.Log(fields=fields, fmtstr=fmtstr,
                                           cvsfilename='send_log.csv', print_raw=self.is_alive())

        # loop with callback to print_event
        b = self.b
        b["send_rcl"].open_perf_buffer(self.print_rcl)
        b["send_fastrtps"].open_perf_buffer(self.print_fastrtps)
        b["send_cyclonedds"].open_perf_buffer(self.print_cyclonedds)

        while not self.set.is_set():
            try:
                b.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
        self.log.close()
        print("[trace_send] Exit")


if __name__ == "__main__":
    config = {'whitelist': False, 'blacklist': False}

    cflags = []
    if config['whitelist']:
        cflags.append('-DWHITELIST=1')
    b = BPF(src_file='./ebpf_ros2.c', cflags=cflags)

    trace = trace_send(args=({'set': multiprocessing.Event(), 'config': config, 'b': b}))
    trace.run()