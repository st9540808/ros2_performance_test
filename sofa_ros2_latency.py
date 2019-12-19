#!/usr/bin/python3

with open('talker_ebpf.data', 'r') as t, \
     open('listener_ebpf.data') as l:
     for t_line, l_line in zip(t, l):
         print(float(l_line) - float(t_line))