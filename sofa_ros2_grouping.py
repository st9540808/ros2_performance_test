#!/usr/bin/python3

import pandas as pd
from pandas import DataFrame as df

def extract_individual_rosmsg(df_send, df_recv, *df_others):
    """ Return a dictionary with topic name as key and
        a list of ros message as value.
        Structure of return value: {topic_name: {(guid, seqnum): log}}
        where (guid, seqnum) is a msg_id
    """
    #  publish side
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

            send_idx = df.loc[(df['ts'] > ts) & (df['layer'] == 'fastrtps')]['ts'].idxmin()
            df_send_partial.loc[send_idx, 'seqnum'] = add_data_call.loc['seqnum']

            send_idx2 = df.loc[(df['ts'] > df.loc[send_idx, 'ts']) & (df['layer'] == 'fastrtps')]['ts'].idxmin()
            df_send_partial.loc[send_idx2, 'seqnum'] = add_data_call.loc['seqnum']

        # get a subscrption from log
        df = all_subscriptions_log[guid]
        df_recv_partial = all_subscriptions_log[guid].copy()
        add_recvchange_calls = df[~pd.isna(df['seqnum'])] # get all not nan seqnums in log
        for idx, add_recvchange_call in add_recvchange_calls.iterrows():
            ts = add_recvchange_call['ts']

            rmw_take_idx = df.loc[(df['ts'] > ts) & (df['layer'] == 'rmw')]['ts'].idxmin()
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

if __name__ == "__main__":
    read_csv = lambda filename: pd.read_csv(filename, dtype={'pid':'Int32', 'seqnum':'Int64'})
    df_send = read_csv('send_log.csv')
    df_cls_egress = read_csv('cls_bpf_log.csv')
    df_recv = read_csv('recv_log.csv')

    res = extract_individual_rosmsg(df_send, df_recv, df_cls_egress)
    print_all_msgs(res)