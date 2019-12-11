#define KBUILD_MODNAME "foo"
#include <uapi/linux/bpf.h>
#include <linux/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/udp.h>

static inline int get_data(void *data, void *data_end) {
    u16 msg2len[23] = {
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
        0, //0x15
        0, //0x16
    };
    u8 *cursor = data;
    u8 msg_id = 0;
    u8 off = 0;

    if (cursor + 20 > data_end) return 0;
    cursor += 20;

    #pragma unroll
    for (int i = 0; i < 4 && msg_id != 0x15; i++) {
        if (cursor + 1 > data_end) return 0;
        msg_id = *cursor;
        switch (msg_id) {
        case 0x09: off = 12; break; // INFO_TS
        case 0x0e: off = 16; break; // INFO_DST
        default: off = 0;
        }
        if (cursor + off > data_end) return 0;
        cursor += off;
    }

    if (off = 0) return 0;
    if (msg_id == 0x15)

    // if (cursor + msg2len[msg_id] > data_end) return 0;
    // cursor += msg2len[msg_id];

    return msg_id;
}

static inline int is_rtps(void *data, void *data_end) {
    char *str = data;

    if (data + 4 > data_end)
        return 0;
    if (str[0] == 'R' && str[1] == 'T' && str[2] == 'P' && str[3] == 'S')
        return 1;
    return 0;
}

// return transport protocol
static inline int parse_ipv4(void *data, void *data_end) {
    struct iphdr *iph = data + sizeof(struct ethhdr);

    if ((void*)&iph[1] > data_end)
        return 0;
    return iph->protocol;
}

// return ethertype
static inline u16 parse_eth(void *data, void *data_end) {
    struct ethhdr *eth = data;
    u64 nh_off = 0;

    nh_off = sizeof(*eth);
    if (data + nh_off > data_end)
        return 0;
    return eth->h_proto;
}

int xdp_prog(struct CTXTYPE *ctx) {
    void *data_end = (void *)(long) ctx->data_end;
    void *data = (void *)(long) ctx->data;

    int rc = RETURNCODE; // let pass XDP_PASS or redirect to tx via XDP_TX
    void *cursor = data; // current offset
    long *value;
    u16 rtps_size;
    u16 len = data_end - data;

    u64 start = bpf_ktime_get_ns();

    if (parse_eth(data, data_end) == htons(ETH_P_IP)
        && parse_ipv4(data, data_end) == IPPROTO_UDP) {
        cursor += sizeof(struct ethhdr);
        cursor += ((struct iphdr *) cursor)->ihl * 4;
    } else
        return rc;

    if (cursor + sizeof(struct udphdr) > data_end)
        return rc;
    // udp len includes header size
    rtps_size = ntohs(((struct udphdr *)(cursor))->len) - 8;

    cursor += sizeof(struct udphdr);
    if (!is_rtps(cursor, data_end))
        return rc;

    // to access payload
    if (data + len > data_end)
        return rc;

    if (!get_data(cursor, data_end))
        return rc;

    bpf_trace_printk("len=%u msg_id=%d bpf_time=%lu\n",
                     rtps_size, get_data(cursor, data_end), bpf_ktime_get_ns()-start);
    return rc;

    // value = dropcnt.lookup(&index);
    // if (value)
    //    __sync_fetch_and_add(value, 1);
}