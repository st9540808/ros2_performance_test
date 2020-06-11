#!/usr/bin/python3

import rclpy
import time

rclpy.init()
node = rclpy.create_node('list_all_topics_example')
time.sleep(1)

print(node.get_topic_names_and_types(no_demangle=False))
