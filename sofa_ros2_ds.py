#!/usr/bin/python3
import csv
import glob
import os
import re
import datetime
import itertools
import json
import numpy as np
import subprocess
import sys
import socket
from bs4 import BeautifulSoup
from distutils.dir_util import copy_tree

from sofa_print import *

def ds_preprocess(cfg):
    from sofa_preprocess import sofa_preprocess
    from sofa_analyze import sofa_analyze

    save_logdir = cfg.logdir
    # ds_logpath = cfg.logdir + "ds_finish/"
    # os.chdir(ds_logpath)

    nodes_record_dir = []
    for dir in filter(lambda x: os.path.isdir(x), os.listdir('.')):
        if dir.find('_sofalog') == -1:
            continue
        nodes_record_dir.append(dir)

    sofa_timebase_min = sys.maxsize
    for i in range(len(nodes_record_dir)):
        time_fd = open('%s/sofa_time.txt' % nodes_record_dir[i])
        unix_time = time_fd.readline()
        unix_time.rstrip()
        unix_time = float(unix_time)

        # get minimum timebase among sofalog directories
        sofa_timebase_min = min(sofa_timebase_min, unix_time)

    for i in range(len(nodes_record_dir)):
        time_fd = open('%s/sofa_time.txt' % nodes_record_dir[i])
        unix_time = time_fd.readline()
        unix_time.rstrip()
        unix_time = float(unix_time)
        cfg.cpu_time_offset = 0
        if (unix_time > sofa_timebase_min):
            basss = float(sofa_timebase_min) - float(unix_time)
            if basss < -28700:
                basss += 28800
            cfg.cpu_time_offset = basss
            # cfg.cpu_time_offset = float(sofa_timebase_min) - float(unix_time)
        print("%s, %f" % (nodes_record_dir[i], cfg.cpu_time_offset))

        cfg.logdir = './' + str(nodes_record_dir[i]) + '/'
        sofa_preprocess(cfg)
        cfg.logdir = save_logdir
        sofa_analyze(cfg)

    # pid2y_pos_dic = ds_connect_preprocess(cfg)
    # dds_calc_topic_latency(cfg)
    #ds_dds_create_span(cfg)

def ds_viz(cfg):
    nodes_record_dir = []
    for dir in filter(lambda x: os.path.isdir(x), os.listdir('.')):
        if dir.find('_sofalog') == -1:
            continue
        nodes_record_dir.append(dir)

    local = os.path.basename(os.path.dirname(cfg.logdir))
    idx = nodes_record_dir.index(local)
    nodes_record_dir.pop(idx)

    master = BeautifulSoup(open(os.path.join(cfg.logdir, 'index.html')), 'html.parser')

    for dir in nodes_record_dir:
        with open(os.path.join(dir, 'index.html')) as f:
            dir_index_soup = BeautifulSoup(f, 'html.parser')
            sofa_fig = dir_index_soup.find('div', id='container')
            sofa_fig['id'] = 'container' + '2'

        with open(os.path.join(dir, 'timeline.js')) as f:
            sofa_fig_highchart = f.read()
            sofa_fig_highchart = sofa_fig_highchart.replace('container',
                                                            'container' + '2')

        report   = master.new_tag('script', src=os.path.join(dir, 'report.js'))
        timeline = master.new_tag('script', src=os.path.join(dir, 'timeline.js'))

        master.body.append(sofa_fig)
        master.body.append(report)
        master.body.append(timeline)
        
        copied_sofalog_dir = os.path.join(local, dir)
        copy_tree(dir, copied_sofalog_dir)
        with open(os.path.join(copied_sofalog_dir, 'timeline.js'), 'w') as f:
            f.write(sofa_fig_highchart)

        print(master.prettify())

    with open(os.path.join(cfg.logdir, 'index.html'), 'w') as f:
        f.write(master.prettify())