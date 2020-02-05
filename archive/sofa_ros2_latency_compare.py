#!/usr/bin/python3

import json

data_list = []
latencies = []
with open('talker_ebpf.data', 'r') as t, \
     open('listener_ebpf_compare.data', 'r') as l:
     for t_line, l_line in zip(t, l):
         latency = float(l_line) - float(t_line) + -0.04373455047607422
         print(latency)
         latencies.append(latency)

with open('sofalog/sofa_time.txt') as s:
    sofa_time = float(s.readline())

with open('talker_ebpf.data', 'r') as t:
    for line, latency in zip(t, latencies):
        data = {}
        data['x'] = float(line) - sofa_time
        data['y'] = latency * 1e3 # ms
        data_list.append(data)

# output = {'name': 'ROS message latency', 'color': 'DeepPink'}
# output['data'] = data_list
print('data = ' + json.dumps([[round(1 * i, 2), round(latencies[i] * 1e3, 5)] for i in range(len(latencies))]))