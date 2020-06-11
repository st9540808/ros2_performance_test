# Copyright 2016 Open Source Robotics Foundation, Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import rclpy
from rclpy.node import Node

from std_msgs.msg import String
from rclpy.executors import SingleThreadedExecutor


class MinimalSubscriber(Node):

    def __init__(self, name):
        super().__init__(name)
        self.cnt = 0
        self.subscription = self.create_subscription(
            String,
            'chatter',
            self.listener_callback,
            10)
        self.subscription  # prevent unused variable warning
        # self.subscription2 = self.create_subscription(
        #     String,
        #     'chatter',
        #     self.listener_callback
        # )

    def listener_callback(self, msg):
        self.cnt += 1
        #self.get_logger().info('I heard: "%s"' % msg.data)


def main(args=None):
    rclpy.init(args=args)

    minimal_subscriber = MinimalSubscriber('minimal_subscriber')
    minimal_subscriber2 = MinimalSubscriber('minimal_subscriber2')
    #minimal_subscriber3 = MinimalSubscriber('minimal_subscriber3')
    #minimal_subscriber4 = MinimalSubscriber('minimal_subscriber4')

    executor = SingleThreadedExecutor()
    executor.add_node(minimal_subscriber)
    executor.add_node(minimal_subscriber2)
    #executor.add_node(minimal_subscriber3)
    #executor.add_node(minimal_subscriber4)

    # Destroy the node explicitly
    # (optional - otherwise it will be done automatically
    # when the garbage collector destroys the node object)

    try:
        executor.spin()
    finally:
        executor.shutdown()
        minimal_subscriber.destroy_node()
        minimal_subscriber2.destroy_node()

    rclpy.shutdown()


if __name__ == '__main__':
    main()
