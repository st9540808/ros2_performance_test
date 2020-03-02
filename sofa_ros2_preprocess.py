#!/usr/bin/python3

import sys
import pandas as pd
from pandas import DataFrame as df
import functools, itertools
import sofa_time
import statistics
import multiprocessing as mp

sys.path.insert(0, '/home/st9540808/Desktop/VS_Code/sofa/bin')
import sofa_models, sofa_preprocess

colors = ['DeepPink']
color = itertools.cycle(colors)

def extract_individual_rosmsg(df_send, df_recv, *df_others):
    """ Return a dictionary with topic name as key and
        a list of ros message as value.
        Structure of return value: {topic_name: {(guid, seqnum): log}}
        where (guid, seqnum) is a msg_id
    """
    # Convert timestamp to unix time
    unix_time_off = statistics.median(sofa_time.get_unix_mono_diff() for i in range(100))
    for df in (df_send, df_recv, *df_others):
        df['ts'] = df['ts'] + unix_time_off

    # publish side
    gb_send = df_send.groupby('guid')
    all_publishers_log = {guid:log for guid, log in gb_send}

    # subscription side
    gb_recv = df_recv.groupby('guid')
    all_subscriptions_log = {guid:log for guid, log in gb_recv}

    # other logs (assume there's no happen-before relations that needed to be resolved)
    # every dataframe is a dictionary in `other_log_list`
    gb_others = [df_other.groupby('guid') for df_other in df_others]
    other_log_list = [{guid:log for guid, log in gb_other} for gb_other in gb_others]

    # find guids that are in both subsciption and publisher log
    interested_guids = all_subscriptions_log.keys() \
                     & all_publishers_log.keys()

    res = {}
    for guid in interested_guids:
        # get a publisher from log
        df = all_publishers_log[guid]
        df_send_partial = all_publishers_log[guid].copy()
        add_data_calls = df[~pd.isna(df['seqnum'])] # get all non-NaN seqnums in log
        for idx, add_data_call in add_data_calls.iterrows():
            ts = add_data_call['ts']

            rcl_idx = df.loc[(df['ts'] < ts) & (df['layer'] == 'rcl')]['ts'].idxmax()
            df_send_partial.loc[rcl_idx, 'seqnum'] = add_data_call.loc['seqnum']

            # send_idx = df.loc[(df['ts'] > ts) & (df['layer'] == 'fastrtps')]['ts'].idxmin()
            # df_send_partial.loc[send_idx, 'seqnum'] = add_data_call.loc['seqnum']

            # send_idx2 = df.loc[(df['ts'] > df.loc[send_idx, 'ts']) & (df['layer'] == 'fastrtps')]['ts'].idxmin()
            # df_send_partial.loc[send_idx2, 'seqnum'] = add_data_call.loc['seqnum']

        # get a subscrption from log
        df = all_subscriptions_log[guid]
        df_recv_partial = all_subscriptions_log[guid].copy()
        add_recvchange_calls = df[~pd.isna(df['seqnum'])] # get all not nan seqnums in log
        for idx, add_recvchange_call in add_recvchange_calls.iterrows():
            ts = add_recvchange_call['ts']
            subaddr = add_recvchange_call['subscriber']

            rmw_take_idx = df.loc[(df['ts'] > ts) &
                                  (df['layer'] == 'rmw') &
                                  (df['subscriber'] == subaddr)]['ts'].idxmin()
            df_recv_partial.loc[rmw_take_idx, 'seqnum'] = add_recvchange_call.loc['seqnum']

        df_merged = df_send_partial.append(df_recv_partial, ignore_index=True, sort=False)

        # handle other log files
        for other_log in other_log_list:
            df_other = other_log[guid]
            df_merged = df_merged.append(df_other, ignore_index=True, sort=False)

        df_merged.sort_values(by=['ts'], inplace=True)
        gb_merged = df_merged.groupby(['guid', 'seqnum'])

        ros_msgs = {msg_id:log for msg_id, log in gb_merged} # msg_id: (guid, seqnum)
        topic_name = next(iter(ros_msgs.items()))[1]['topic_name'].any()
        res[topic_name] = ros_msgs
    return res

def print_all_msgs(res):
    for topic_name, all_msgs_log in res.items():
        print('topic: ' + topic_name)
        for (guid, seqnum), msg_log in all_msgs_log.items():
            print('msg_id: ', (guid, seqnum))
            print(msg_log)
            print('')

def ros_msgs_trace_read(items, cfg):
    # ts	layer	func	comm	pid	topic_name	guid	seqnum	subscriber
    # 1	321114.175064	rcl	NaN	talker	4109.0	/chatter	1.f.ec.5f.d.10.0.0.1.0.0.0|0.0.10.3	1.0	NaN
    # 2	321114.175964	fastrtps	RTPSMessageGroup::add_data	talker	4115.0	NaN	1.f.ec.5f.d.10.0.0.1.0.0.0|0.0.10.3	1.0	NaN
    # 3	321114.176010	fastrtps	RTPSMessageGroup::send	talker	4115.0	NaN	1.f.ec.5f.d.10.0.0.1.0.0.0|0.0.10.3	1.0	NaN
    # 4	321114.176166	fastrtps	RTPSMessageGroup::send	talker	4115.0	NaN	1.f.ec.5f.d.10.0.0.1.0.0.0|0.0.10.3	1.0	NaN
    # 61	321114.176288	cls_egress	NaN	NaN	NaN	NaN	1.f.ec.5f.d.10.0.0.1.0.0.0|0.0.10.3	1.0	NaN
    # 62	321114.176329	cls_ingress	NaN	NaN	NaN	NaN	1.f.ec.5f.d.10.0.0.1.0.0.0|0.0.10.3	1.0	NaN
    # 41	321114.177028	fastrtps	add_received_change	listener	4125.0	NaN	1.f.ec.5f.d.10.0.0.1.0.0.0|0.0.10.3	1.0	9.427450e+13
    # 42	321114.178160	rmw	rmw_take_with_info exit	listener	4120.0	NaN	1.f.ec.5f.d.10.0.0.1.0.0.0|0.0.10.3	1.0	9.427450e+13
    sofa_fieldnames = [
        "timestamp",  # 0
        "event",      # 1
        "duration",   # 2
        "deviceId",   # 3
        "copyKind",   # 4
        "payload",    # 5
        "bandwidth",  # 6
        "pkt_src",    # 7
        "pkt_dst",    # 8
        "pid",        # 9
        "tid",        # 10
        "name",       # 11
        "category",   # 12
        "unit"]

    traces = []
    topic_name, all_msgs_log = items
    for msg_id, msg_log in all_msgs_log.items():
        trace = dict(zip(sofa_fieldnames, itertools.repeat(-1)))
        start = msg_log.iloc[0]
        end = msg_log.iloc[-1]

        time = start['ts']
        if cfg is not None and not cfg.absolute_timestamp:
            time = start['ts'] - cfg.time_base
        trace['timestamp'] = time
        trace['duration'] = (end['ts'] - start['ts']) * 1e3 # ms
        trace['name'] = "[%s] %s -> [%s] %s <br>Topic Name: %s" % \
                        (start['layer'], start['func'], end['layer'], end['func'], start['topic_name'])
        trace['unit'] = 'ms'
        traces.append(trace)
    traces = pd.DataFrame(traces)
    return traces

def run(cfg):
    """ Start preprocessing. """
    # Read all log files generated by ebpf_ros2_*
    read_csv = functools.partial(pd.read_csv, dtype={'pid':'Int32', 'seqnum':'Int64'})
    cvs_files_others = ['cls_bpf_log.csv']
    df_send = read_csv('send_log.csv')
    df_recv = read_csv('recv_log.csv')
    df_others = []
    for csv_file in cvs_files_others:
        try:
            df_others.append(read_csv(csv_file))
        except pd.errors.EmptyDataError as e:
            print(csv_file + ' is empty')

    all_msgs = extract_individual_rosmsg(df_send, df_recv, *df_others)
    print(all_msgs)
    with mp.Pool(processes=4) as pool:
        res = pool.map(functools.partial(ros_msgs_trace_read, cfg=cfg), all_msgs.items())

    sofatrace = sofa_models.SOFATrace()
    sofatrace.name = 'ros2_latency'
    sofatrace.title = 'ROS2 latency'
    sofatrace.color = next(color)
    sofatrace.x_field = 'timestamp'
    sofatrace.y_field = 'duration'
    sofatrace.data = res[0] # TODO: append all
    return sofatrace

if __name__ == "__main__":
    # read_csv = functools.partial(pd.read_csv, dtype={'pid':'Int32', 'seqnum':'Int64'})
    # df_send = read_csv('send_log.csv')
    # df_cls = read_csv('cls_bpf_log.csv')
    # df_recv = read_csv('recv_log.csv')
    # res = extract_individual_rosmsg(df_send, df_recv, df_cls)
    # print_all_msgs(res)

    run(None)