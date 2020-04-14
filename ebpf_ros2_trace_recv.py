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

# define BPF program
prog = r"""
#include <linux/sched.h>
#define RMW_GID_STORAGE_SIZE 24

// define output data structure in C
struct rcl_data_t {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
};

struct rmw_data_t {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char func[32];
    char implementation[24];

    void *subscriber;
    u8 guid[16];
};

struct fastrtps_data_t {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char func[28];

    void *subscriber;
    u8 guid[16];
    u64 seqnum;
};

BPF_PERF_OUTPUT(rmw);
BPF_PERF_OUTPUT(fastrtps);

// definition of some rmw structures
typedef struct rmw_gid_t {
  const char * implementation_identifier;
  uint8_t data[RMW_GID_STORAGE_SIZE];
} rmw_gid_t;
typedef struct rmw_message_info_t {
  rmw_gid_t publisher_gid;
  bool from_intra_process;
} rmw_message_info_t;
typedef struct rmw_subscription_t {
  const char * implementation_identifier;
  void * data;
  const char * topic_name;
} rmw_subscription_t;

typedef struct rmw_take_metadata_t {
    rmw_message_info_t *msginfo;
    void *subscriber; // for implementation specific data type
    rmw_subscription_t *subscription;
} rmw_take_metadata_t;

int rmw_wait_retprobe(struct pt_regs *ctx) {
    struct rmw_data_t data = {};

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof data.comm);
    strcpy(data.func, "rmw_wait exit");

    rmw.perf_submit(ctx, &data, sizeof(struct rmw_data_t));
    return 0;
}

BPF_HASH(message_info_hash, u32, rmw_take_metadata_t);
#define subscriber__OFF 8
int rmw_take_with_info_retprobe(struct pt_regs *ctx) {
    struct rmw_data_t data = {};
    rmw_take_metadata_t *metadata;
    rmw_message_info_t *message_info;
    rmw_subscription_t *subscription;
    char *ptr;
    u32 pid;

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof data.comm);
    strcpy(data.func, "rmw_take_with_info exit");

    metadata = message_info_hash.lookup(&data.pid);
    if (!metadata)
        return 0;

    // get subscriber address from metadata
    data.subscriber = metadata->subscriber;
    subscription = metadata->subscription;
    bpf_probe_read(&ptr, sizeof(char *), &subscription->implementation_identifier);
    bpf_probe_read_str(data.implementation, sizeof data.implementation, ptr);

    switch (data.implementation[4]) {
    case 'f': // rmw_fastrtps_cpp
        // get guid
        message_info = metadata->msginfo;
        bpf_probe_read(data.guid, 16, message_info->publisher_gid.data);

        //message_info_hash.delete(&data.pid);
        break;
    case 'c':
        if (data.implementation[5] == 'y') { // rmw_cyclonedds_cpp

        }
    default:
        break;
    }
    rmw.perf_submit(ctx, &data, sizeof(struct rmw_data_t));
    return 0;
}
int rmw_take_with_info_probe(struct pt_regs *ctx, void *subscription,
                             void *ros_message, bool *taken, void *message_info) {
    rmw_take_metadata_t metadata = {};
    void *ptr, *subscriber;
    u32 pid;

    pid = bpf_get_current_pid_tgid();
    //data.ts = bpf_ktime_get_ns();
    //bpf_get_current_comm(&data.comm, sizeof data.comm);
    //strcpy(data.func, "rmw_take_with_info enter");

    // get memory address of subscriber
    bpf_probe_read(&ptr, sizeof(void *), &((rmw_subscription_t *) subscription)->data);
    bpf_probe_read(&subscriber, sizeof(void *), (ptr + subscriber__OFF));

    // pass subscriber address to return probe
    metadata.msginfo = message_info;
    metadata.subscriber = subscriber;
    metadata.subscription = subscription;
    message_info_hash.update(&pid, &metadata);

    //rmw.perf_submit(ctx, &data, sizeof(struct rmw_data_t));
    return 0;
}

#define OFF_WRITERGUID 4
#define OFF_SEQNUM 36
#define mp_subImpl_OFF 336
#define mp_userSubscriber_OFF 11896
int add_received_change_probe(struct pt_regs *ctx, void *this, void *change) {
    struct fastrtps_data_t data = {};
    void *mp_subImpl;
    s32 high;
    u32 low;

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof data.comm);
    strcpy(data.func, "add_received_change");

    // read sequence number
    bpf_probe_read(&high, 4, (change + OFF_SEQNUM));
    bpf_probe_read(&low, 4, (change + OFF_SEQNUM + 4));
    data.seqnum = (((u64) high) << 32u) | low;

    // read guid
    bpf_probe_read(data.guid, 16, (change + OFF_WRITERGUID));

    // read subscriber memory address
    bpf_probe_read(&mp_subImpl, sizeof(void *), (this + mp_subImpl_OFF));
    bpf_probe_read(&data.subscriber, sizeof(void *), (mp_subImpl + mp_userSubscriber_OFF));

    fastrtps.perf_submit(ctx, &data, sizeof(struct fastrtps_data_t));
    return 0;
}
"""

class trace_recv(multiprocessing.Process):
    @perf_callback_factory(event_name='rmw',
                           data_keys=['ts', 'implementation', 'func', 'comm', 'subscriber', 'pid', 'guid'])
    def print_rmw(self, *args):
        pass

    @perf_callback_factory(event_name='fastrtps',
                           data_keys=['func', 'ts', 'comm', 'pid', 'subscriber', 'guid', 'seqnum'])
    def print_fastrtps(self, *args):
        pass

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.set = kwargs['args'][0] if 'args' in kwargs else multiprocessing.Event()

    def run(self):
        # load BPF program
        self.b = b = BPF(text=prog)
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

        # header
        fields = ['layer', 'ts', 'implementation', 'func', 'comm', 'pid', 'subscriber', 'guid', 'seqnum']
        fmtstr = '{:<10} {:<14.4f} {:<24} {:<28} {:<11} {:<8} {:<#18x} {:<40} {:<3d}'
        self.log = sofa_ros2_utilities.Log(fields=fields, fmtstr=fmtstr,
                                           cvsfilename='recv_log.csv', print_raw=self.is_alive())

        # loop with callback to print_event
        b["rmw"].open_perf_buffer(self.print_rmw)
        b["fastrtps"].open_perf_buffer(self.print_fastrtps)
        while not self.set.is_set():
            try:
                b.perf_buffer_poll(timeout=1000)
            except KeyboardInterrupt:
                break
        self.log.close()

if __name__ == "__main__":
    trace = trace_recv()
    trace.run()