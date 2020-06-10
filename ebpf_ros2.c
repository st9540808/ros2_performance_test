#include <linux/sched.h>
#include <linux/types.h>
#include <uapi/linux/ptrace.h>

typedef struct topic_key {
    u32 prefixlen;
    char topic_name[40];
} topic_key_t;

BPF_LPM_TRIE(whitelist, topic_key_t, u8);

/////////////////////////////////////////////////////////////////////////////////////
// Send
/////////////////////////////////////////////////////////////////////////////////////
// define output data structure in C
typedef struct send_rcl_data {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char implementation[24];
    char topic_name[40];
    void *publisher;
    void *ros_message;

    //void *rmw_data;
    void *rmw_publisher_;
    u8    rmw_guid[16];
    //char  rmw_tsid[36]; //typesupport_identifier_

    void *mp_impl;
    void *mp_writer;
} send_rcl_data_t;

typedef struct send_fastrtps_data {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char func[28];

    void *endpoint;
    u8 ep_guid[16];
    u64 seqnum;
    u32 daddr;
    u16 dport;
} send_fastrtps_data_t;

typedef struct send_cyclonedds_data {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char func[24];

    void *publisher;
    u8 guid[16];
    u64 seqnum;
    u32 daddr;
    u16 dport;
} send_cyclonedds_data_t;

BPF_PERF_OUTPUT(send_rcl);
BPF_PERF_OUTPUT(send_fastrtps);
BPF_PERF_OUTPUT(send_cyclonedds);

// rmw layer
typedef struct rmw_publisher_t {
  const char *implementation_identifier;
  void *data;
  const char *topic_name;
} rmw_publisher_t;

// fastrtps
typedef struct Locator_t {
    int32_t kind;
    uint32_t port;
    u8 address[16];
} Locator_t;
// structures for profiling fastrtps
typedef struct locator_key {
    u32 addr;
    u16 port;
} locator_key_t;
typedef struct GUID_t {
    u8 value[16];
} GUID_t;

// cyclonedds
typedef union ddsi_guid {
  u8 s[16];
  u32 u[4];
} ddsi_guid_t;
typedef struct {
  int32_t kind;
  uint32_t port;
  unsigned char address[16];
} nn_locator_t;
// structures for profiling cyclonedds
struct cyclone_pub_key {
    //u32 pubh; // publisher handle
    void *ros_message;
    u32 pid;
};
struct cyclone_pub_val {
    send_rcl_data_t val;
};

BPF_HASH(cyclone_publish, struct cyclone_pub_key, struct cyclone_pub_val);

BPF_HASH(endpoint_hash, void *, GUID_t, 1024); // a set for all endpoints
BPF_HASH(locator_hash, locator_key_t, int, 1024); // a set for all locator
BPF_HASH(guid_hash, GUID_t, int, 1024); // a set for all guid (fastrtps)

#define OFF_RMW_HANDLE 224
#define OFF_RMW_PUBLISHER_ 8
#define OFF_RMW_GUID 40
#define OFF_RMW_TSID 64
#define OFF_MP_IMPL 8
#define OFF_MP_WRITER 16
int rcl_publish_probe(struct pt_regs *ctx, void *publisher, void *ros_message) {
    send_rcl_data_t data = {};
    char *impl, *rmw_data, *rmw_handle;
    void *ptr;
    topic_key_t key = {};
    int len;

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
    len = bpf_probe_read_str(data.topic_name, sizeof data.topic_name, ptr);

    bpf_probe_read(&ptr, sizeof(void *), &((rmw_publisher_t *) rmw_handle)->data);
    rmw_data = ptr;

#ifdef WHITELIST
    // filter topics (whitelist)
    key.prefixlen = len * 8;
    memcpy(key.topic_name, data.topic_name, 40);
    if (!whitelist.lookup(&key))
        return 0;
#endif

    switch (data.implementation[4]) {
    case 'f': // rmw_fastrtps_cpp
        // `CustomPublisherInfo`, get information pointed by data in rmw_publisher
        bpf_probe_read(&data.rmw_publisher_, sizeof(void *), (rmw_data + OFF_RMW_PUBLISHER_));
        bpf_probe_read(data.rmw_guid, sizeof data.rmw_guid,  (rmw_data + OFF_RMW_GUID + 8));
#ifdef WHITELIST
        guid_hash.update((void *) data.rmw_guid, &(int){0x1});
#endif

        // `eprosima::fastrtps::PublisherImpl`
        bpf_probe_read(&data.mp_impl, sizeof(void *), (data.rmw_publisher_ + OFF_MP_IMPL));
        bpf_probe_read(&data.mp_writer, sizeof(void *), (data.mp_impl + OFF_MP_WRITER));
        endpoint_hash.update(&data.mp_writer, (void *) data.rmw_guid);
        break;
    case 'c': // can be rmw_cyclonedds_cpp or rmw_connext_cpp
        if (data.implementation[5] == 'y') { // rmw_cyclonedds_cpp
            struct cyclone_pub_key key = {};

            //bpf_probe_read(&key.pubh, sizeof(s32), rmw_data);
            key.ros_message = ros_message;
            key.pid = data.pid;
            data.ts = bpf_ktime_get_ns(); // record timestamp at the end of this eBPF program
            cyclone_publish.update(&key, (struct cyclone_pub_val *) &data);
            return 0;
        }
    default:
        break;
    }

    data.ts = bpf_ktime_get_ns(); // record timestamp at the end of this eBPF program
    send_rcl.perf_submit(ctx, &data, sizeof(send_rcl_data_t));
    return 0;
}

BPF_HASH(whc_guid_hash, void *, ddsi_guid_t);
BPF_HASH(nn_xpack_guid_hash, void *, ddsi_guid_t);
#define m_guid_OFF 88
#define m_whc_OFF  560
#define m_xp_OFF   544
int cyclone_dds_write_impl_probe(struct pt_regs *ctx, void *wr, void *data) {
    // defer to this function to output data. Memory address of datawriter is not
    // visible in rcl_publish, because cyclonedds uses an integer handle to represent an object.
    struct cyclone_pub_key key = {};
    send_rcl_data_t *val;
    u32 pid;
    void *m_xp; // struct nn_xpack*
    ddsi_guid_t *guid;

    key.ros_message = data;
    key.pid = bpf_get_current_pid_tgid();
    val = (send_rcl_data_t *) cyclone_publish.lookup(&key);
    if (!val)
        return 0;

    // read guid
    guid = (ddsi_guid_t *) val->rmw_guid;
    bpf_probe_read(guid, sizeof val->rmw_guid, (wr + m_guid_OFF));
    guid->u[3] = cpu_to_be32(guid->u[3]); // change to big endian

    // read m_whc and m_xp
    bpf_probe_read(&val->mp_writer, sizeof val->mp_writer, (wr + m_whc_OFF));
    bpf_probe_read(&m_xp, sizeof m_xp, (wr + m_xp_OFF));

    // associate guid with address of whc and m_xp
    whc_guid_hash.update(&val->mp_writer, guid);
    nn_xpack_guid_hash.update(&m_xp, guid);

    send_rcl.perf_submit(ctx, val, sizeof(send_rcl_data_t));
    return 0;
}

int cyclone_whc_default_insert_seq(struct pt_regs *ctx, void *whc, int64_t max_drop_seq, int64_t seq) {
    send_cyclonedds_data_t data = {};
    ddsi_guid_t *guid;

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof data.comm);
    strcpy(data.func, "whc_default_insert_seq");

    // read m_whc and seqnum
    data.publisher = whc;
    data.seqnum = seq;

    // read guid from hash
    guid = whc_guid_hash.lookup(&data.publisher);
    if (!guid)
        return 0;
    memcpy(data.guid, guid, sizeof *guid);

    send_cyclonedds.perf_submit(ctx, &data, sizeof(send_cyclonedds_data_t));
    return 0;
}

// trace write_sample_gc using a uprobe and uretprobe because sequence number
// is updated in this function
#define seq_OFF 240
#define whc_OFF 392
typedef struct write_sample_gc_val {
    u64 ts;
    void *wr;
} write_sample_gc_val_t;
BPF_HASH(write_sample_gc, u32, write_sample_gc_val_t);
int cyclone_write_sample_gc(struct pt_regs *ctx, void *arg0, void *arg1, void *wr) {
    write_sample_gc_val_t val = {};
    u32 pid = bpf_get_current_pid_tgid();
    val.ts = bpf_ktime_get_ns();
    val.wr = wr;
    write_sample_gc.update(&pid, &val);
    return 0;
}
int cyclone_write_sample_gc_retprobe(struct pt_regs *ctx) {
    send_cyclonedds_data_t data = {};
    write_sample_gc_val_t *val_ptr;
    ddsi_guid_t *guid;

    data.pid = bpf_get_current_pid_tgid();
    val_ptr = write_sample_gc.lookup(&data.pid);
    if (!val_ptr)
        return 0;

    // look up guid by whc
    bpf_probe_read(&data.publisher, sizeof(void *), (val_ptr->wr + whc_OFF));
    guid = whc_guid_hash.lookup(&data.publisher);
    if (!guid)
        return 0;

    data.ts = val_ptr->ts;
    bpf_get_current_comm(&data.comm, sizeof data.comm);
    strcpy(data.func, "write_sample_gc");

    // read guid and seqnum
    memcpy(data.guid, guid, sizeof *guid);
    bpf_probe_read(&data.seqnum, sizeof data.seqnum, (val_ptr->wr + seq_OFF));
    send_cyclonedds.perf_submit(ctx, &data, sizeof(send_cyclonedds_data_t));
    return 0;
}

#define nn_xpack__conn_OFF 80 // source port is stored in nn_xpack
#define nn_locator_t__port_OFF 4 // destination port is stored in nn_locator_t
int cyclone_nn_xpack_send1(struct pt_regs *ctx, void *loc, void *varg) {
    send_cyclonedds_data_t data = {};
    ddsi_guid_t *guid;

    // read guid from hash
    guid = nn_xpack_guid_hash.lookup(&varg);
    if (!guid)
        return 0;
    memcpy(data.guid, guid, sizeof *guid);

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof data.comm);
    strcpy(data.func, "nn_xpack_send1");

    // read port
    bpf_probe_read(&data.dport, sizeof(u16), (loc + nn_locator_t__port_OFF));
    data.dport = cpu_to_be16(data.dport);

    send_cyclonedds.perf_submit(ctx, &data, sizeof(send_cyclonedds_data_t));
    return 0;
}

#define OFF_WRITERGUID 4
#define OFF_SEQNUM 36

#define OFF_ENDPOINT 8
#define OFF_M_GUID 16
int fastrtps_send_probe(struct pt_regs *ctx, void *this) {
    send_fastrtps_data_t data = {};
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

    send_fastrtps.perf_submit(ctx, &data, sizeof(send_fastrtps_data_t));
    return 0;
}
int fastrtps_add_data_probe(struct pt_regs *ctx, void *this, void *change) {
   send_fastrtps_data_t data = {};
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

    send_fastrtps.perf_submit(ctx, &data, sizeof(send_fastrtps_data_t));
    return 0;
}

BPF_HASH(add_pub_change_hash, u32, void *, 1024);
int fastrtps_add_pub_change_probe(struct pt_regs *ctx, void *this, void *change) {
    u32 pid;
    pid = bpf_get_current_pid_tgid();
    add_pub_change_hash.update(&pid, &change);
    return 0;
}
int fastrtps_add_pub_change_retprobe(struct pt_regs *ctx) {
    send_fastrtps_data_t data = {};
    void **change_ptr, *change;
    s32 high;
    u32 low;

    data.pid = bpf_get_current_pid_tgid();
    change_ptr = add_pub_change_hash.lookup(&data.pid);
    if (!change_ptr)
        return 0;

    change = *change_ptr;
    data.ts = bpf_ktime_get_ns();
    //data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof data.comm);
    strcpy(data.func, "add_pub_change");

    // read sequence number
    bpf_probe_read(&high, 4, (change + OFF_SEQNUM));
    bpf_probe_read(&low, 4, (change + OFF_SEQNUM + 4));
    data.seqnum = (((u64) high) << 32u) | low;

    // read guid
    // (although we read from the field writerGUID, we will still store it in ep_guid)
    bpf_probe_read(data.ep_guid, 16, (change + OFF_WRITERGUID));

    send_fastrtps.perf_submit(ctx, &data, sizeof(send_fastrtps_data_t));
    return 0;
}

BPF_HASH(RTPSMessageGroup_hash, u32, void *, 1024);
int fastrtps_RTPSMessageGroup_destructor_probe(struct pt_regs *ctx, void *this) {
    send_fastrtps_data_t data = {};
    GUID_t *exist;

    // get endpoint memory address and check presence in hash
    bpf_probe_read(&data.endpoint, sizeof(void *), (this + OFF_ENDPOINT));
    exist = endpoint_hash.lookup(&data.endpoint);
    if (!exist)
        return 0;

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    strcpy(data.func, "~RTPSMessageGroup");

    // store this pointer
    RTPSMessageGroup_hash.update(&data.pid, &this);

    send_fastrtps.perf_submit(ctx, &data, sizeof(send_fastrtps_data_t));
    return 0;
}
int fastrtps_RTPSMessageGroup_destructor_retprobe(struct pt_regs *ctx) {
    send_fastrtps_data_t data = {};
    void **this_ptr, *this;

    // get this pointer
    data.pid = bpf_get_current_pid_tgid();
    this_ptr = RTPSMessageGroup_hash.lookup(&data.pid);
    if (!this_ptr)
        return 0;
    this = *this_ptr;
    RTPSMessageGroup_hash.delete(&data.pid);

    data.ts = bpf_ktime_get_ns();
    strcpy(data.func, "~RTPSMessageGroup exit");

    // get endpoint memory address
    bpf_probe_read(&data.endpoint, sizeof(void *), (this + OFF_ENDPOINT));
    send_fastrtps.perf_submit(ctx, &data, sizeof(send_fastrtps_data_t));
    return 0;
}
int fastrtps_RTPSParticipantImpl_sendSync_probe(struct pt_regs *ctx, void *this,
                                                void *msg, void *pend, Locator_t *destination_loc) {
    send_fastrtps_data_t data = {};
    GUID_t *exist;
    locator_key_t *lk = (void *) &data.daddr;

    exist = endpoint_hash.lookup(&pend);
    if (!exist)
        return 0;

    data.ts = bpf_ktime_get_ns();
    data.endpoint = pend;
    strcpy(data.func, "sendSync");
    bpf_probe_read(&data.daddr, 4,  destination_loc->address + 12);
    bpf_probe_read(&data.dport, 2, &destination_loc->port);
    data.dport = cpu_to_be16(data.dport);

    // store locator
    locator_hash.update(lk, &(int){0x1});

    memcpy(data.ep_guid, exist, sizeof data.ep_guid);

    send_fastrtps.perf_submit(ctx, &data, sizeof(send_fastrtps_data_t));
    return 0;
}
int fastrtps_UDPTransportInterface_send_probe(struct pt_regs *ctx, void *this, void *send_buffer,
                                              uint32_t send_buffer_size, void *socket,
                                              Locator_t *remote_locator) {
    send_fastrtps_data_t data = {};
    locator_key_t *lk = (void *) &data.daddr;
    int *exist;

    bpf_probe_read(&data.daddr, 4,  remote_locator->address + 12);
    bpf_probe_read(&data.dport, 2, &remote_locator->port);
    data.dport = cpu_to_be16(data.dport);
    exist = locator_hash.lookup(lk);
    if (!exist)
        return 0;

    data.ts = bpf_ktime_get_ns();
    strcpy(data.func, "UDPTransportInterface::send");

    send_fastrtps.perf_submit(ctx, &data, sizeof(send_fastrtps_data_t));
    return 0;
}

/////////////////////////////////////////////////////////////////////////////////////
// Receive
/////////////////////////////////////////////////////////////////////////////////////
#define RMW_GID_STORAGE_SIZE 24

// define output data structure in C
typedef struct recv_rcl_data {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
} recv_rcl_data_t;

typedef struct recv_rmw_data {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char func[32];
    char implementation[24];
    char topic_name[40];

    void *subscriber;
    u8 guid[16];
} recv_rmw_data_t;

typedef struct recv_fastrtps_data {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char func[28];

    void *subscriber;
    u8 guid[16];
    u64 seqnum;
    u32 saddr;
    u16 sport;
    u32 daddr;
    u16 dport;
} recv_fastrtps_data_t;

typedef struct recv_cyclonedds_data {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char func[24];

    void *subscriber;
    u8 guid[16];
    u64 seqnum;
    u32 saddr;
    u16 sport;
    u32 daddr;
    u16 dport;
} recv_cyclonedds_data_t;

BPF_PERF_OUTPUT(recv_rmw);
BPF_PERF_OUTPUT(recv_fastrtps);
BPF_PERF_OUTPUT(recv_cyclonedds);

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

// Type used to trace ROS2
typedef struct rmw_take_metadata_t {
    union {
        rmw_message_info_t *msginfo;
        ddsi_guid_t *cyclone_guid;
    } info;
    void *subscriber; // for implementation specific data type
    rmw_subscription_t *subscription;
} rmw_take_metadata_t;

BPF_HASH(message_info_hash, u32, rmw_take_metadata_t, 1024);
BPF_HASH(cyclone_take_hash, struct cyclone_pub_key, int, 1024); // a set for (ros_message, pid)
BPF_HASH(cyclone_rhc_guid_hash, void *, ddsi_guid_t, 1024); // map pointer to rhc to guid

int rmw_wait_retprobe(struct pt_regs *ctx) {
    recv_rmw_data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
#ifdef WHITELIST
    // reduce log record size
    if (!message_info_hash.lookup(&data.pid))
        return 0;
#endif

    data.ts = bpf_ktime_get_ns();
    bpf_get_current_comm(&data.comm, sizeof data.comm);
    strcpy(data.func, "rmw_wait exit");

    recv_rmw.perf_submit(ctx, &data, sizeof(recv_rmw_data_t));
    return 0;
}

#define subscriber__OFF 8
int rmw_take_with_info_retprobe(struct pt_regs *ctx) {
    recv_rmw_data_t data = {};
    rmw_take_metadata_t *metadata;
    rmw_message_info_t *message_info;
    rmw_subscription_t *subscription;
    ddsi_guid_t *guid;
    char *ptr;
    u32 pid;

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    metadata = message_info_hash.lookup(&data.pid);
    if (!metadata)
        return 0;

    bpf_get_current_comm(&data.comm, sizeof data.comm);
    strcpy(data.func, "rmw_take_with_info exit");

    // get subscriber address from metadata
    data.subscriber = metadata->subscriber;
    subscription = metadata->subscription;
    bpf_probe_read(&ptr, sizeof(char *), &subscription->implementation_identifier);
    bpf_probe_read_str(data.implementation, sizeof data.implementation, ptr);
    bpf_probe_read(&ptr, sizeof(char *), &subscription->topic_name);
    bpf_probe_read_str(data.topic_name, sizeof data.topic_name, ptr);

    // TODO: Add topic filter here, and move message_info_hash.lookup below topic filter

    switch (data.implementation[4]) {
    case 'f': // rmw_fastrtps_cpp
        // get guid
        message_info = metadata->info.msginfo;
        bpf_probe_read(data.guid, 16, message_info->publisher_gid.data);

        //message_info_hash.delete(&data.pid);
        break;
    case 'c':
        if (data.implementation[5] == 'y') { // rmw_cyclonedds_cpp
            guid = cyclone_rhc_guid_hash.lookup(&data.subscriber);
            if (!guid)
                return 0;
            memcpy(data.guid, guid, sizeof(ddsi_guid_t));
        }
    default:
        break;
    }
    recv_rmw.perf_submit(ctx, &data, sizeof(recv_rmw_data_t));
    return 0;
}
int rmw_take_with_info_probe(struct pt_regs *ctx, void *subscription,
                             void *ros_message, bool *taken, void *message_info) {
    rmw_take_metadata_t metadata = {};
    void *ptr, *subscriber;
    u32 pid;
    char implementation[32];

    pid = bpf_get_current_pid_tgid();
    //data.ts = bpf_ktime_get_ns();
    //bpf_get_current_comm(&data.comm, sizeof data.comm);
    //strcpy(data.func, "rmw_take_with_info enter");

    bpf_probe_read(&ptr, sizeof(char *), &((rmw_subscription_t *) subscription)->implementation_identifier);
    bpf_probe_read_str(implementation, sizeof implementation, ptr);
    if (implementation[4] == 'f') { // rmw_fastrtps_cpp
        // get memory address of subscriber
        bpf_probe_read(&ptr, sizeof(void *), &((rmw_subscription_t *) subscription)->data);
        bpf_probe_read(&subscriber, sizeof(void *), (ptr + subscriber__OFF));
        metadata.subscriber = subscriber;
        metadata.info.msginfo = message_info;
    } else if (implementation[5] == 'y') { // rmw_cyclonedds_cpp
        struct cyclone_pub_key key = {};
        key.ros_message = ros_message;
        key.pid = pid;
        cyclone_take_hash.update(&key, &(int){0x1});
    }

    // pass subscriber address to return probe
    metadata.subscription = subscription;
    message_info_hash.update(&pid, &metadata);

    //recv_rmw.perf_submit(ctx, &data, sizeof(recv_rmw_data_t));
    return 0;
}

#define OFF_WRITERGUID 4
#define OFF_SEQNUM 36
#define mp_subImpl_OFF 336
#define mp_userSubscriber_OFF 11896
int add_received_change_probe(struct pt_regs *ctx, void *this, void *change) {
    recv_fastrtps_data_t data = {};
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

    recv_fastrtps.perf_submit(ctx, &data, sizeof(recv_fastrtps_data_t));
    return 0;
}

//_ZN8eprosima8fastrtps4rtps18UDPChannelResource24perform_listen_operationENS1_9Locator_tE
// BPF_HASH(local_locator_hash, void *, locator_key_t);
// int fastrtps_UDPChannelResource_perform_listen_operation(struct pt_regs *ctx, void *this,
//                                                          Locator_t *local_locator) {
//     recv_fastrtps_data_t data = {};
//     data.ts = bpf_ktime_get_ns();
//     bpf_get_current_comm(&data.comm, sizeof data.comm);
//     strcpy(data.func, "perform_listen_operation");
//     memcpy(&data.daddr, local_locator->address + 12, 4);
//     memcpy(&data.dport, local_locator->port, 2);
//     data.dport = cpu_to_be16(data.dport);

//     recv_fastrtps.perf_submit(ctx, &data, sizeof(recv_fastrtps_data_t));
//     return 0;
// }

BPF_HASH(locator_to_guid_hash, locator_key_t, GUID_t, 1024);
BPF_HASH(fastrtps_UDPReceive_hash, u32, void *, 1024);
#define message_receiver__OFF 56
int fastrtps_UDPChannelResource_Receive_probe(struct pt_regs *ctx, void *this,
                                              void *arg0, void *arg1, void *arg2,
                                              Locator_t *remote_locator) {
    void *message_receiver_;
    u32 pid = bpf_get_current_pid_tgid();
    bpf_probe_read(&message_receiver_, sizeof(void *), this + message_receiver__OFF);
    fastrtps_UDPReceive_hash.update(&pid, &message_receiver_);
    return 0;
}
BPF_HASH(UDPReceive_rettime_hash, void *, u64, 1024);
int fastrtps_UDPChannelResource_Receive_retprobe(struct pt_regs *ctx) {
    void **this_ptr;
    u64 ts;
    u32 pid;

    ts = bpf_ktime_get_ns();
    pid = bpf_get_current_pid_tgid();
    this_ptr = fastrtps_UDPReceive_hash.lookup(&pid);
    if (!this_ptr)
        return 0;

    UDPReceive_rettime_hash.update(this_ptr, &ts);
    return 0;
}
// _ZN8eprosima8fastrtps4rtps16ReceiverResource14OnDataReceivedEPKhjRKNS1_9Locator_tES7_
int fastrtps_ReceiverResource_OnDataReceived_probe(struct pt_regs *ctx, void *this,
                                                   const void *_data, const uint32_t size,
                                                   const Locator_t *localLocator, const Locator_t *remoteLocator)
{
    recv_fastrtps_data_t data = {};
    GUID_t *guid_ptr;
    locator_key_t *lk = (void *) &data.saddr;
    u64 *ts_ptr;

    bpf_probe_read(&data.saddr, 4,  remoteLocator->address + 12);
    bpf_probe_read(&data.sport, 2, &remoteLocator->port);
    data.sport = cpu_to_be16(data.sport);

    guid_ptr = locator_to_guid_hash.lookup(lk);
    if (!guid_ptr)
        return 0;

    ts_ptr = UDPReceive_rettime_hash.lookup(&this);
    if (!ts_ptr)
        return 0;

    bpf_probe_read(&data.daddr, 4,  localLocator->address + 12);
    bpf_probe_read(&data.dport, 2, &localLocator->port);
    data.dport = cpu_to_be16(data.dport);

    data.ts = *ts_ptr;
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof data.comm);
    memcpy(data.guid, guid_ptr, sizeof data.guid);
    strcpy(data.func, "UDPResourceReceive exit");

    recv_fastrtps.perf_submit(ctx, &data, sizeof(recv_fastrtps_data_t));
    return 0;
}

/////////////////////////////////////////////////////////////////////////////////////
// cyclone DDS

// `ddsrt_recvmsg_hash` maps pid to recv_cyclonedds_data_t,
// the value will be written by multiple eBPF programs
// (see who calls ddsrt_recvmsg.lookup())
BPF_HASH(ddsrt_recvmsg_hash, u32, recv_cyclonedds_data_t, 512);
int cyclone_ddsi_udp_conn_read_probe(struct pt_regs *ctx, void *conn, unsigned char * buf,
                                     size_t len, bool allow_spurious, nn_locator_t *srcloc)
{
    recv_cyclonedds_data_t data = {};
    u32 pid = bpf_get_current_pid_tgid();
    data.pid = pid;
    ddsrt_recvmsg_hash.update(&pid, &data);
    return 0;
}
int cyclone_ddsrt_recvmsg_retprobe(struct pt_regs *ctx)
{
    recv_cyclonedds_data_t *data_ptr;
    int ret = PT_REGS_RC(ctx);
    u32 pid;
    u64 ts;

    if (ret == -53) //  <+185>:   cmp    eax,0xffffffcb
        return 0;

    pid = bpf_get_current_pid_tgid();
    data_ptr = ddsrt_recvmsg_hash.lookup(&pid);
    if (!data_ptr)
        return 0;
    data_ptr->ts = bpf_ktime_get_ns();
    return 0;
}
/*
BPF_HASH(ddsi_udp_conn_hash, u32, void *, 1024);
BPF_HASH(conn_to_recvmsg_ts, void *, u64, 1024);
int cyclone_ddsi_udp_conn_read_retprobe(struct pt_regs *ctx)
{
    u32 pid;
    void **conn_ptr;
    u64 *ts_ptr;

    // get pointer to conn
    pid = bpf_get_current_pid_tgid();
    conn_ptr = ddsi_udp_conn_hash.lookup(&pid);
    if (!conn_ptr)
        return 0;

    // get timestamp when recvmsg returns
    ts_ptr = ddsrt_recvmsg_hash.lookup(&pid);
    if (!ts_ptr)
        return 0;

    ddsrt_recvmsg_hash.delete(&pid);
    conn_to_recvmsg_ts.update(conn_ptr, ts_ptr); // associate pointer to conn with a timetamp
    return 0;
}
*/

#define rst_OFF 8
#define conn_OFF 40
int cyclone_handle_regular_probe(struct pt_regs *ctx, void *rst, int64_t tnow, void *rmsg, void *msg, void *sampleinfo, u32 fragnum)
{
    recv_cyclonedds_data_t data = {};
    data.pid = bpf_get_current_pid_tgid();
    strcpy(data.func, "handle_regular");

    data.subscriber = sampleinfo;

    bpf_probe_read(&data.seqnum, sizeof data.seqnum, sampleinfo);
    recv_cyclonedds.perf_submit(ctx, &data, sizeof(recv_cyclonedds_data_t));
    return 0;
}
int cyclone_deliver_user_data_probe(struct pt_regs *ctx, void *sampleinfo)
{
    recv_cyclonedds_data_t *data_ptr;
    u32 pid;
    void *rst;
    void *conn;
    u64 *ts_ptr;

    pid = bpf_get_current_pid_tgid();
    data_ptr = ddsrt_recvmsg_hash.lookup(&pid);
    if (!data_ptr)
        return 0;

    bpf_probe_read(&rst, sizeof(void *), sampleinfo + rst_OFF);
    bpf_probe_read(&conn, sizeof(void *), rst + conn_OFF);

    // read seqnum
    bpf_probe_read(&data_ptr->seqnum, sizeof data_ptr->seqnum, sampleinfo);

    // read port
    bpf_probe_read(&data_ptr->dport, sizeof(u16), conn);
    data_ptr->dport = cpu_to_be16(data_ptr->dport);
    return 0;
}
int cyclone_dds_rhc_default_store_probe(struct pt_regs *ctx, void *rhc, void *wrinfo)
{
    recv_cyclonedds_data_t *data_ptr;
    ddsi_guid_t *guid;
    u32 pid;

    pid = bpf_get_current_pid_tgid();
    data_ptr = ddsrt_recvmsg_hash.lookup(&pid);
    if (!data_ptr)
        return 0;

    strcpy(data_ptr->func, "ddsi_udp_conn_read exit");
    bpf_get_current_comm(data_ptr->comm, sizeof data_ptr->comm);
    data_ptr->subscriber = rhc;

    // read guid
    guid = (ddsi_guid_t *) data_ptr->guid;
    bpf_probe_read(guid, sizeof data_ptr->guid, wrinfo);
    guid->u[3] = cpu_to_be32(guid->u[3]); // change to big endian
    cyclone_rhc_guid_hash.update(&rhc, guid);
    recv_cyclonedds.perf_submit(ctx, data_ptr, sizeof(recv_cyclonedds_data_t));
    return 0;
}

int cyclone_dds_rhc_default_take_wrap_probe(struct pt_regs *ctx, void *rhc, bool lock, void **values)
{
    struct cyclone_pub_key key = {};
    rmw_take_metadata_t *metadata_ptr;
    ddsi_guid_t *guid;
    u32 pid = bpf_get_current_pid_tgid();

    key.pid = pid;
    bpf_probe_read(&key.ros_message, sizeof(void *), values);
    if (!cyclone_take_hash.lookup(&key))
        return 0;

    metadata_ptr = message_info_hash.lookup(&pid);
    if (!metadata_ptr)
        return 0;

    metadata_ptr->subscriber = rhc;
    return 0;
}

/////////////////////////////////////////////////////////////////////////////////////
// Traffic Control (cls_bpf)
/////////////////////////////////////////////////////////////////////////////////////
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
    u32 saddr;
    u16 sport;
    u32 daddr;
    u16 dport;
    u8 msg_id;
};

BPF_PERF_OUTPUT(cls_egress);
BPF_PERF_OUTPUT(cls_ingress);

static u16 msg2len[23] = {
        0,
        0, //0x01
        0, 0, 0, 0,
        0, //0x06
        32, //0x07 HEARTBEAT
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
        0, //0x16 DATAFRAG
    };

#define RTPS_OFF (ETH_HLEN + sizeof(struct iphdr) + sizeof(struct udphdr))
#define RTPS_HLEN 20
#define RTPS_VENDORID_OFF 6
#define RTPS_GUIDPREFIX_OFF 8
#define RTPS_DATA_WRITERID_OFF 12
#define RTPS_DATA_SEQNUM_OFF 16
#define RTPS_SUBMSG_ID_DATA 0x15
#define RTPS_SUBMSG_ID_DATAFRAG 0x16
// find the offset to the submsg in a RTPS message
static int find_rtps_data_submsg(struct __sk_buff *skb, u8 *msg_id) {
    int off = 0;
    *msg_id = 0;
    #pragma unroll
    for (int i = 0; i < 4 && !(*msg_id == 0x15 || *msg_id == 0x16); i++) {
        bpf_skb_load_bytes(skb, RTPS_OFF + RTPS_HLEN + off, msg_id, 1);

        switch (*msg_id) {
        case 0x09: off += 12; break; // INFO_TS
        case 0x0e: off += 16; break; // INFO_DST
        case 0x07: off += 32; break; // HEARTBEAT
        default: off += 0;
        }
    }
    return off;
}

static void get_vendor_id(struct __sk_buff *skb, u16 *vendorid) {
    bpf_skb_load_bytes(skb, RTPS_OFF + RTPS_VENDORID_OFF, vendorid, 2);
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

static void fix_guidprefix_endianness(u8 *guid, u16 vendorid) {
    uint32_t *ptr = (uint32_t *) guid; // first byte
    // check if using cyclonedds
    if (vendorid == 0x1001) {
        #pragma unroll
        for (int i = 0; i < 3; i++, ptr++)
            *ptr = be32_to_cpu(*ptr);
    }
}

static int is_builtin_entites(u8 *guid) {
    u8 entityKind = guid[15];
    if ((entityKind & 0xc0) == 0xc0)
        return 1;
    return 0;
}

int cls_ros2_egress_prog(struct __sk_buff *skb) {
    struct cls_egress_data_t data = {};
    char *magic = data.magic;
    u16 vendorid = 0;
    u8 msg_id = 0;
    int off = 0;

    bpf_skb_load_bytes(skb, RTPS_OFF, &data.magic, 4);
    data.magic[4] = 0;

    if (!(magic[0] == 'R' && magic[1] == 'T' && magic[2] == 'P' && magic[3] == 'S'))
        return TC_ACT_PIPE;

    bpf_skb_load_bytes(skb, ETH_HLEN + 16, &data.daddr, 4);
    bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr) + 2, &data.dport, 2);
    bpf_skb_load_bytes(skb, ETH_HLEN + 12, &data.saddr, 4);
    bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr) + 0, &data.sport, 2);
    get_vendor_id(skb, &vendorid);
    off = find_rtps_data_submsg(skb, &msg_id);

    if (msg_id == RTPS_SUBMSG_ID_DATA || msg_id == RTPS_SUBMSG_ID_DATAFRAG) {
        get_guid_seqnum(skb, off, data.guid, &data.seqnum);
        if (is_builtin_entites(data.guid))
            return TC_ACT_PIPE;
        fix_guidprefix_endianness(data.guid, vendorid);
        data.ts = bpf_ktime_get_ns();
        data.msg_id = msg_id;
        cls_egress.perf_submit(skb, &data, sizeof(struct cls_egress_data_t));
    }
    return TC_ACT_PIPE;
}

int cls_ros2_ingress_prog(struct __sk_buff *skb) {
    struct cls_egress_data_t data = {};
    char *magic = data.magic;
    u16 vendorid = 0;
    u8 msg_id = 0;
    int off = 0;
    locator_key_t *lk = (void *) &data.saddr; // for fastrtps

    bpf_skb_load_bytes(skb, RTPS_OFF, &data.magic, 4);
    data.magic[4] = 0;

    if (!(magic[0] == 'R' && magic[1] == 'T' && magic[2] == 'P' && magic[3] == 'S'))
        return TC_ACT_PIPE;

    bpf_skb_load_bytes(skb, ETH_HLEN + 16, &data.daddr, 4);
    bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr) + 2, &data.dport, 2);
    bpf_skb_load_bytes(skb, ETH_HLEN + 12, &data.saddr, 4);
    bpf_skb_load_bytes(skb, ETH_HLEN + sizeof(struct iphdr) + 0, &data.sport, 2);
    get_vendor_id(skb, &vendorid);
    off = find_rtps_data_submsg(skb, &msg_id);

    if (msg_id != RTPS_SUBMSG_ID_DATA && msg_id != RTPS_SUBMSG_ID_DATAFRAG)
        return TC_ACT_PIPE;

    get_guid_seqnum(skb, off, data.guid, &data.seqnum);
    if (is_builtin_entites(data.guid))
        return TC_ACT_PIPE;
    fix_guidprefix_endianness(data.guid, vendorid);
    data.ts = bpf_ktime_get_ns();
    data.msg_id = msg_id;
    cls_ingress.perf_submit(skb, &data, sizeof(struct cls_egress_data_t));

    locator_to_guid_hash.update(lk, (void *) &data.guid);

    return TC_ACT_PIPE;
}