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
    u32 addr;
    u16 port;
} send_fastrtps_data_t;

typedef struct send_cyclonedds_data {
    u64 ts;
    u32 pid;
    char comm[TASK_COMM_LEN];
    char func[28];

    void *publisher;
    u8 guid[16];
    u64 seqnum;
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

BPF_HASH(endpoint_hash, void *, GUID_t); // a set for all endpoints
BPF_HASH(locator_hash, locator_key_t, int); // a set for all locator
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
    len = bpf_probe_read_str(data.topic_name, sizeof data.topic_name, ptr);

    bpf_probe_read(&ptr, sizeof(void *), &((rmw_publisher_t *) rmw_handle)->data);
    rmw_data = ptr;

    // filter topics (whitelist)
    key.prefixlen = len * 8;
    memcpy(key.topic_name, data.topic_name, 40);
    if (!whitelist.lookup(&key))
        return 0;

    switch (data.implementation[4]) {
    case 'f': // rmw_fastrtps_cpp
        // `CustomPublisherInfo`, get information pointed by data in rmw_publisher
        bpf_probe_read(&data.rmw_publisher_, sizeof(void *), (rmw_data + OFF_RMW_PUBLISHER_));
        bpf_probe_read(data.rmw_guid, sizeof data.rmw_guid,  (rmw_data + OFF_RMW_GUID + 8));

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
            cyclone_publish.update(&key, (struct cyclone_pub_val *) &data);
            return 0;
        }
    default:
        break;
    }

    send_rcl.perf_submit(ctx, &data, sizeof(send_rcl_data_t));
    return 0;
}

BPF_HASH(whc_hash, void *, ddsi_guid_t);
BPF_HASH(nn_xpack_hash, void *, ddsi_guid_t);
#define m_guid_OFF 88
#define m_whc_OFF  560
#define m_xp_OFF   544
int cyclone_dds_write_impl_probe(struct pt_regs *ctx, void *wr, void *data) {
    // defer to this function to output data. Memory address of datawriter is not
    // visible in rcl_publish, because cyclonedds use an integer handle to represent an object.
    struct cyclone_pub_key key = {};
    send_rcl_data_t *val;
    u32 pid;
    void *m_xp;
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
    whc_hash.update(&val->mp_writer, guid);
    nn_xpack_hash.update(&m_xp, guid);

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
    guid = whc_hash.lookup(&data.publisher);
    if (!guid)
        return 0;
    memcpy(data.guid, guid, sizeof *guid);

    send_cyclonedds.perf_submit(ctx, &data, sizeof(send_cyclonedds_data_t));
    return 0;
}

#define seq_OFF 240
int cyclone_write_sample_gc(struct pt_regs *ctx, void *arg0, void *arg1, void *wr) {
    send_cyclonedds_data_t data = {};

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof data.comm);
    strcpy(data.func, "write_sample_gc");

    bpf_probe_read(&data.seqnum, sizeof data.seqnum, (wr + seq_OFF));
    send_cyclonedds.perf_submit(ctx, &data, sizeof(send_cyclonedds_data_t));
    return 0;
}

int cyclone_nn_xpack_send1(struct pt_regs *ctx, void *loc, void *varg) {
    send_cyclonedds_data_t data = {};
    ddsi_guid_t *guid;

    // read guid from hash
    guid = nn_xpack_hash.lookup(&varg);
    if (!guid)
        return 0;
    memcpy(data.guid, guid, sizeof *guid);

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof data.comm);
    strcpy(data.func, "nn_xpack_send1");

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

BPF_HASH(add_pub_change_hash, u32, void *);
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

BPF_HASH(RTPSMessageGroup_hash, u32, void *);
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
    locator_key_t *lk = (void *) &data.addr;

    exist = endpoint_hash.lookup(&pend);
    if (!exist)
        return 0;

    data.ts = bpf_ktime_get_ns();
    data.endpoint = pend;
    strcpy(data.func, "sendSync");
    bpf_probe_read(&data.addr, 4,  destination_loc->address + 12);
    bpf_probe_read(&data.port, 2, &destination_loc->port);
    data.port = cpu_to_be16(data.port);

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
    locator_key_t *lk = (void *) &data.addr;
    int *exist;

    bpf_probe_read(&data.addr, 4,  remote_locator->address + 12);
    bpf_probe_read(&data.port, 2, &remote_locator->port);
    data.port = cpu_to_be16(data.port);
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
} recv_fastrtps_data_t;

BPF_PERF_OUTPUT(recv_rmw);
BPF_PERF_OUTPUT(recv_fastrtps);

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
    rmw_message_info_t *msginfo;
    void *subscriber; // for implementation specific data type
    rmw_subscription_t *subscription;
} rmw_take_metadata_t;

int rmw_wait_retprobe(struct pt_regs *ctx) {
    recv_rmw_data_t data = {};

    data.ts = bpf_ktime_get_ns();
    data.pid = bpf_get_current_pid_tgid();
    bpf_get_current_comm(&data.comm, sizeof data.comm);
    strcpy(data.func, "rmw_wait exit");

    recv_rmw.perf_submit(ctx, &data, sizeof(recv_rmw_data_t));
    return 0;
}

BPF_HASH(message_info_hash, u32, rmw_take_metadata_t);
#define subscriber__OFF 8
int rmw_take_with_info_retprobe(struct pt_regs *ctx) {
    recv_rmw_data_t data = {};
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
    bpf_probe_read(&ptr, sizeof(char *), &subscription->topic_name);
    bpf_probe_read_str(data.topic_name, sizeof data.topic_name, ptr);

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
    recv_rmw.perf_submit(ctx, &data, sizeof(recv_rmw_data_t));
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