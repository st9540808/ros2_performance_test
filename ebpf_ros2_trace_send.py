#!/usr/bin/python3

from __future__ import print_function
from bcc import BPF
from bcc.utils import printb
import multiprocessing
import json
import sofa_time
import sofa_ros2_utilities
from sofa_ros2_utilities import perf_callback_factory

# define BPF program
prog = r"""
#include <linux/sched.h>

// define output data structure in C
struct rcl_data_t {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char implementation[36];
    char topic_name[36];
    void *publisher;
    void *ros_message;

    void *rmw_data;
    void *rmw_publisher_;
    u8    rmw_guid[16];
    //char  rmw_tsid[36]; //typesupport_identifier_

    void *mp_impl;
    void *mp_writer;
};

struct fastrtps_data_t {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char func[28];

    void *endpoint;
    u8 ep_guid[16];
    u64 seqnum;
};

BPF_PERF_OUTPUT(rcl);
BPF_PERF_OUTPUT(fastrtps);

typedef struct rmw_publisher_t {
  const char *implementation_identifier;
  void *data;
  const char *topic_name;
} rmw_publisher_t;

int publish_probe(struct pt_regs *ctx, void *publisher) {
    struct rcl_data_t data = {};

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    data.publisher = publisher;
    const void *ptr = ((rmw_publisher_t *) publisher)->implementation_identifier;
    bpf_probe_read(data.implementation, 16, (char *) ptr);

    ptr = ((rmw_publisher_t *) publisher)->topic_name;
    bpf_probe_read_str(data.topic_name, sizeof data.topic_name, (char *) ptr);

    data.ros_message = ((rmw_publisher_t *) publisher)->data;

    rcl.perf_submit(ctx, &data, sizeof(struct rcl_data_t));
    return 0;
}

#define OFF_RMW_HANDLE 224
#define OFF_RMW_PUBLISHER_ 8
#define OFF_RMW_GUID 40
#define OFF_RMW_TSID 64
#define OFF_MP_IMPL 8
#define OFF_MP_WRITER 16
int rcl_publish_probe(struct pt_regs *ctx, void *publisher, void *ros_message) {
    struct rcl_data_t data = {};
    char *impl, *rmw_handle;
    void *ptr;

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    data.ros_message = ros_message;
    bpf_get_current_comm(&data.comm, sizeof data.comm);

    data.publisher = publisher;
    bpf_probe_read(&impl, sizeof impl, publisher);
    impl += OFF_RMW_HANDLE;

    bpf_probe_read(&rmw_handle, sizeof rmw_handle, impl);
    if (!rmw_handle)
        return 0;

    // `rmw_publisher_t`
    bpf_probe_read(&ptr, sizeof(char *), &((rmw_publisher_t *) rmw_handle)->implementation_identifier);
    bpf_probe_read_str(data.implementation, sizeof data.implementation, ptr);

    bpf_probe_read(&ptr, sizeof(char *), &((rmw_publisher_t *) rmw_handle)->topic_name);
    bpf_probe_read_str(data.topic_name, sizeof data.topic_name, ptr);

    bpf_probe_read(&ptr, sizeof(void *), &((rmw_publisher_t *) rmw_handle)->data);
    data.rmw_data = ptr;

    switch (data.implementation[4]) {
    case 'f': // rmw_fastrtps_cpp
        // `CustomPublisherInfo`, get information pointed by data in rmw_publisher
        bpf_probe_read(&data.rmw_publisher_, sizeof(void *), (data.rmw_data + OFF_RMW_PUBLISHER_));
        bpf_probe_read(data.rmw_guid, sizeof data.rmw_guid,  (data.rmw_data + OFF_RMW_GUID));

        // `eprosima::fastrtps::PublisherImpl`
        bpf_probe_read(&data.mp_impl, sizeof(void *), (data.rmw_publisher_ + OFF_MP_IMPL));
        bpf_probe_read(&data.mp_writer, sizeof(void *), (data.mp_impl + OFF_MP_WRITER));
        break;
    default:
        break;
    }

    rcl.perf_submit(ctx, &data, sizeof(struct rcl_data_t));
    return 0;
}


#define OFF_WRITERGUID 4
#define OFF_SEQNUM 36

#define OFF_ENDPOINT 8
#define OFF_M_GUID 16
int fastrtps_send_probe(struct pt_regs *ctx, void *this) {
    struct fastrtps_data_t data = {};
    s32 high;
    u32 low;

    bpf_probe_read(&data.endpoint, sizeof(void *), (this + OFF_ENDPOINT));
    bpf_probe_read(data.ep_guid, sizeof data.ep_guid, (data.endpoint + OFF_M_GUID));

    if ((data.ep_guid[15] & 0xc0) == 0xc0)
        return 0;

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof data.comm);
    strcpy(data.func, "RTPSMessageGroup::send");

    fastrtps.perf_submit(ctx, &data, sizeof(struct fastrtps_data_t));
    return 0;
}
int fastrtps_add_data_probe(struct pt_regs *ctx, void *this, void *change) {
    struct fastrtps_data_t data = {};
    s32 high;
    u32 low;

    bpf_probe_read(&data.endpoint, sizeof(void *), (this + OFF_ENDPOINT));
    bpf_probe_read(data.ep_guid, sizeof data.ep_guid, (data.endpoint + OFF_M_GUID));

    // ignore builtin entities
    if ((data.ep_guid[15] & 0xc0) == 0xc0)
        return 0;

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof data.comm);
    strcpy(data.func, "RTPSMessageGroup::add_data");

    bpf_probe_read(&high, 4, (change + OFF_SEQNUM));
    bpf_probe_read(&low, 4, (change + OFF_SEQNUM + 4));
    data.seqnum = (((u64) high) << 32u) | low;

    fastrtps.perf_submit(ctx, &data, sizeof(struct fastrtps_data_t));
    return 0;
}
"""

class trace_send(multiprocessing.Process):
    @perf_callback_factory(event_name='rcl',
                           data_keys=['ts', 'comm', 'pid', 'topic_name', 'mp_writer', 'rmw_guid'],
                           remap={'mp_writer':'publisher', 'rmw_guid':'guid'})
    def print_rcl(self, *args):
        pass

    @perf_callback_factory(event_name='fastrtps',
                           data_keys=['func', 'ts', 'comm', 'pid', 'endpoint', 'ep_guid', 'seqnum'],
                           remap={'endpoint':'publisher', 'ep_guid':'guid'})
    def print_fastrtps(self, *args):
        d = args[0]
        if d['seqnum'] == 0:
            d.pop('seqnum')

    def run(self):
        # load BPF program
        self.b = b = BPF(text=prog)
        b.attach_uprobe(name="/home/st9540808/Desktop/VS_Code/ros2-build_from_source/build/rcl/librcl.so",
                        sym="rcl_publish",
                        fn_name="rcl_publish_probe")
        b.attach_uprobe(name="/home/st9540808/Desktop/VS_Code/ros2-build_from_source/install/fastrtps/lib/libfastrtps.so.1.8.2",
                        sym="_ZN8eprosima8fastrtps4rtps16RTPSMessageGroup4sendEv",
                        fn_name="fastrtps_send_probe")
        b.attach_uprobe(name="/home/st9540808/Desktop/VS_Code/ros2-build_from_source/install/fastrtps/lib/libfastrtps.so.1.8.2",
                        sym="_ZN8eprosima8fastrtps4rtps16RTPSMessageGroup8add_dataERKNS1_13CacheChange_tERKSt6vectorINS1_6GUID_tESaIS7_EERKNS1_13LocatorList_tEb",
                        fn_name="fastrtps_add_data_probe")

        # header:  ts        layer  func   comm   pid   topic  pub      guid   seqnum
        fmtstr = '{:<13.5f} {:<10} {:<28} {:<16} {:<8} {:<22}          {:<40} {:<3d}'
        fields = ['ts', 'layer', 'func', 'comm', 'pid', 'topic_name', 'guid', 'seqnum']
        self.log = sofa_ros2_utilities.Log(fields=fields, fmtstr=fmtstr,
                                           cvsfilename='send_log.csv', print_raw=self.is_alive())

        # loop with callback to print_event
        b["rcl"].open_perf_buffer(self.print_rcl)
        b["fastrtps"].open_perf_buffer(self.print_fastrtps)
        while 1:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                break
        self.log.close()

if __name__ == "__main__":
    trace = trace_send()
    trace.run()