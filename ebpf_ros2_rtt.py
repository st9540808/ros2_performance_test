from __future__ import print_function
from bcc import BPF
from time import sleep

# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

BPF_HISTOGRAM(dist);
BPF_ARRAY(start_time, uint64_t, 1);

int rtt_sender__publish_probe(struct pt_regs *ctx) {
    uint64_t curr = bpf_ktime_get_ns();

    start_time.update(&(int){0}, &curr);
    bpf_trace_printk("rtt_sender__publish_probe curr=%lu\\n", curr);
    return 0;
};

int rtt_sender__subscription_probe(struct pt_regs *ctx) {
    uint64_t curr = bpf_ktime_get_ns();
    uint64_t *prev, lat;

    prev = start_time.lookup(&(int){0});
    if (prev) {
        lat = (curr - *prev) / 1000;
        dist.increment(bpf_log2l(lat));
        bpf_trace_printk("rtt_sender__subscription_probe lat=%luusecs\\n", lat);
    }
    return 0;
}
""")

b.attach_uprobe(name="./install/ros_course_demo/lib/ros_course_demo/rtt_sender",
                sym="_ZN6rclcpp9PublisherIN8std_msgs3msg7String_ISaIvEEES4_E7publishERKS5_",
                fn_name="rtt_sender__publish_probe")
b.attach_uprobe(name="./install/ros_course_demo/lib/ros_course_demo/rtt_sender",
                sym="_ZN10RTT_Sender12callback_ackESt10shared_ptrIN8std_msgs3msg7String_ISaIvEEEE",
                fn_name="rtt_sender__subscription_probe")

while 1:
    try:
        try:
            (task, pid, cpu, flags, ts, msg) = b.trace_fields()
        except ValueError:
            continue
        print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))
        # print("%-16s %-6d %s" % (task, pid, msg))
    except KeyboardInterrupt:
        break

print("")
b["dist"].print_log2_hist("usec")