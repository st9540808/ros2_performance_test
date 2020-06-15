#!/usr/bin/python3

import ctypes, os
import time
import sys
import subprocess
import sofa_ros2_utilities
import multiprocessing

__all__ = ["get_monotonic_time"]

CLOCK_MONOTONIC_RAW = 4 # see <linux/time.h>

class timespec(ctypes.Structure):
    _fields_ = [
        ('tv_sec', ctypes.c_long),
        ('tv_nsec', ctypes.c_long)
    ]

librt = ctypes.CDLL('librt.so.1', use_errno=True)
clock_gettime = librt.clock_gettime
clock_gettime.argtypes = [ctypes.c_int, ctypes.POINTER(timespec)]

if not os.path.isfile(os.path.abspath('libtime_adjust_client.so')):
    subprocess.call(['gcc', '-fPIC', '-c', 'time_adjust_client.c'])
    subprocess.call(['gcc', '-shared', '-o', 'libtime_adjust_client.so', 'time_adjust_client.o'])
    subprocess.call(['rm', 'time_adjust_client.o'])
libtime_adjust_client = ctypes.CDLL(os.path.abspath('libtime_adjust_client.so'))
get_time_offset = libtime_adjust_client.get_time_offset
get_time_offset.argtypes = [ctypes.c_char_p, ctypes.POINTER(ctypes.c_double)]

def get_monotonic_time():
    if sys.version_info[0] == 3:
        return time.monotonic()
    t = timespec()
    if clock_gettime(CLOCK_MONOTONIC_RAW , ctypes.pointer(t)) != 0:
        errno_ = ctypes.get_errno()
        raise OSError(errno_, os.strerror(errno_))
    return t.tv_sec + t.tv_nsec * 1e-9

def get_monotonic_time_us():
    if sys.version_info[0] == 3:
        return int(time.monotonic() * 1e6)

def get_uptime():
    with open('/proc/uptime', 'r') as f:
        uptime_seconds = float(f.readline().split()[0])
    return uptime_seconds

def get_unix_mono_diff():
    if sys.version_info[0] < 3:
        return time.time() - get_monotonic_time()
    else:
        return time.time() - time.monotonic()

def get_time_offset_from(serv_addr):
    off = ctypes.c_double()
    if get_time_offset(ctypes.c_char_p(serv_addr.encode('utf-8')),
                       ctypes.byref(off)) == -1:
        print('error in get_time_offset()')
        return 0
    return off.value

def record_time_offset_from(serv_addr, set):
    log = sofa_ros2_utilities.Log(['bios_time', 'time_offset'], '{:<13.5f} {:<13.5f}',
                                  'sofalog/time_offset.csv')
    while not set.is_set():
        try:
            off = get_time_offset_from(serv_addr)
            log.print({'bios_time': time.time(), 'time_offset': off})
            time.sleep(2)
        except KeyboardInterrupt:
            break
    log.close()

class span_server_and_record_from(multiprocessing.Process):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        arg = kwargs['args']
        self.set = arg['set']
        self.serv_addr = arg['serv_addr']

    def run(self):
        server = subprocess.Popen(['./time_adjust_server'])
        record_time_offset_from(self.serv_addr, self.set)
        server.kill()
        print("[span_server_and_record_from] Exit")


if __name__ == "__main__":
    # print(get_monotonic_time())
    # print(time.time() - get_monotonic_time())
    # print(time.monotonic())
    # print(time.time() - time.monotonic())

    # my_list = []
    # for i in range(1000):
    #     data = [int(time.time()*1e3), round(get_time_offset_from('192.168.3.1')*1e3, 6)]
    #     my_list.append(data)

    #     print(data[0], data[1])
    #     time.sleep(0.03)
    # import json
    # with open('./sofalog/time_offset.js', 'w') as f:
    #     f.write('time_offset = ' + json.dumps(my_list))

    print(sys.argv[1])
    sr = span_server_and_record_from(args={'set':multiprocessing.Event(), 'serv_addr': sys.argv[1]})

    sr.start()
    while True:
        try:
            time.sleep(0.1)
        except KeyboardInterrupt as e:
            break
    sr.terminate()