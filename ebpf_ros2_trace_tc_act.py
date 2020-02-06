#!/usr/bin/python3

from bcc import BPF
import pyroute2
import time
import sys
import multiprocessing
import sofa_ros2_utilities
from sofa_ros2_utilities import perf_callback_factory

# device = sys.argv[1]
#mode = BPF.XDP
device = 'lo'
mode = BPF.SCHED_CLS

prog = r"""
#include <uapi/linux/bpf.h>
#include <uapi/linux/pkt_cls.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/if_packet.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/udp.h>
#include <uapi/linux/tcp.h>
#include <uapi/linux/filter.h>
#include <linux/sched.h>

struct cls_egress_data_t {
    u64 ts;
    char magic[8];
    u8 guid[16];
    u64 seqnum;
};

BPF_PERF_OUTPUT(cls_egress);
BPF_PERF_OUTPUT(cls_ingress);

static u16 msg2len[23] = {
        0,
        0, //0x01
        0, 0, 0, 0,
        0, //0x06
        0, //0x07
        0, //0x08
        12, // 0x09 INFO_TS
        0, 0,
        0, //0x0c
        0, //0x0d
        16, // 0x0e INFO_DST
        0, //0x0f
        0, 0,
        0, //0x12
        0, //0x13
        0,
        0, //0x15 DATA
        0, //0x16
    };

#define RTPS_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))
#define RTPS_HLEN 20
#define RTPS_GUIDPREFIX_OFF 8
#define RTPS_DATA_WRITERID_OFF 12
#define RTPS_DATA_SEQNUM_OFF 16
#define RTPS_SUBMSG_ID_DATA 0x15
// find the offset to the submsg in a RTPS message
static int find_rtps_data_submsg(struct __sk_buff *skb, u8 *msg_id) {
    int off = 0;
    *msg_id = 0;
    #pragma unroll
    for (int i = 0; i < 4 && *msg_id != 0x15; i++) {
        bpf_skb_load_bytes(skb, RTPS_OFF + RTPS_HLEN + off, msg_id, 1);

        switch (*msg_id) {
        case 0x09: off += 12; break; // INFO_TS
        case 0x0e: off += 16; break; // INFO_DST
        default: off += 0;
        }
    }
    return off;
}

// get guid and seqnum
static void get_guid_seqnum(struct __sk_buff *skb, int off, u8 *guid, u64 *seqnum) {
    s32 high;
    u32 low;

    bpf_skb_load_bytes(skb, RTPS_OFF + RTPS_GUIDPREFIX_OFF, guid, 12);
    bpf_skb_load_bytes(skb, RTPS_OFF + RTPS_HLEN + off + RTPS_DATA_WRITERID_OFF, &guid[12], 4);
    bpf_skb_load_bytes(skb, RTPS_OFF + RTPS_HLEN + off + RTPS_DATA_SEQNUM_OFF, &high, 4);
    bpf_skb_load_bytes(skb, RTPS_OFF + RTPS_HLEN + off + RTPS_DATA_SEQNUM_OFF + 4, &low, 4);
    *seqnum = (((u64) high) << 32u) | low;
}

int cls_ros2_egress_prog(struct __sk_buff *skb) {
    struct cls_egress_data_t data = {};
    char *magic = data.magic;
    u8 msg_id = 0;
    int off = 0;

    bpf_skb_load_bytes(skb, RTPS_OFF, &data.magic, 4);
    data.magic[4] = 0;

    if (!(magic[0] == 'R' && magic[1] == 'T' && magic[2] == 'P' && magic[3] == 'S'))
        return TC_ACT_OK;

    off = find_rtps_data_submsg(skb, &msg_id);

    if (msg_id == RTPS_SUBMSG_ID_DATA) {
        get_guid_seqnum(skb, off, data.guid, &data.seqnum);
        data.ts = bpf_ktime_get_ns();
        cls_egress.perf_submit(skb, &data, sizeof(struct cls_egress_data_t));
    }
    return TC_ACT_OK;
}

int cls_ros2_ingress_prog(struct __sk_buff *skb) {
    struct cls_egress_data_t data = {};
    char *magic = data.magic;
    u8 msg_id = 0;
    int off = 0;

    bpf_skb_load_bytes(skb, RTPS_OFF, &data.magic, 4);
    data.magic[4] = 0;

    if (!(magic[0] == 'R' && magic[1] == 'T' && magic[2] == 'P' && magic[3] == 'S'))
        return TC_ACT_OK;

    off = find_rtps_data_submsg(skb, &msg_id);

    if (msg_id == RTPS_SUBMSG_ID_DATA) {
        get_guid_seqnum(skb, off, data.guid, &data.seqnum);
        data.ts = bpf_ktime_get_ns();
        cls_ingress.perf_submit(skb, &data, sizeof(struct cls_egress_data_t));
    }
    return TC_ACT_OK;
}
"""

class trace_tc_act(multiprocessing.Process):
    # define callback function for perf events
    @perf_callback_factory('cls_ingress', ['ts', 'magic', 'guid', 'seqnum'])
    def print_cls_ingress(self, *args):
        pass

    @perf_callback_factory('cls_egress', ['ts', 'magic', 'guid', 'seqnum'])
    def print_cls_egress(self, *args):
        pass

    def run(self):
        # load BPF program
        self.b = b = BPF(text=prog)
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

        if not self.is_alive():
            print("Printing, hit CTRL+C to stop")

        # use print_raw if executed as a child
        fields = ['layer', 'ts', 'guid', 'seqnum']
        fmtstr = '{:<20} {:<13.5f} {:<40} {:<3d}'
        self.log = sofa_ros2_utilities.Log(fields=fields, fmtstr=fmtstr,
                                           cvsfilename='cls_bpf_log.csv', print_raw=self.is_alive())

        b["cls_egress"].open_perf_buffer(self.print_cls_egress)
        b["cls_ingress"].open_perf_buffer(self.print_cls_ingress)
        while 1:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                print("Removing filter from device")
                break
        self.log.close()

        ip.tc("del", "clsact", idx)
        ipdb.release()

if __name__ == "__main__":
    trace = trace_tc_act()
    trace.run()