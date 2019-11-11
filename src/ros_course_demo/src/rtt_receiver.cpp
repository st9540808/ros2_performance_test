// Copyright 2014 Open Source Robotics Foundation, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
extern "C" {
#include <unistd.h>
}

#include <cstdio>
#include <memory>
#include <string>
#include <vector>

#include "rclcpp/rclcpp.hpp"

#include "std_msgs/msg/string.hpp"

using namespace std::chrono_literals;

// Create a Listener class that subclasses the generic rclcpp::Node base class.
// The main function below will instantiate the class as a ROS node.
class RTT_Receiver : public rclcpp::Node
{
public:
  RTT_Receiver() : Node("rtt_receiver") {
    // receive incoming data
    sub_send_ = this->create_subscription<std_msgs::msg::String>(
      "rtt_send", rclcpp::QoS(10).reliable(),
      std::bind(&RTT_Receiver::callback_send, this, std::placeholders::_1));
    
    // return an ack to sender
    pub_ack_ = this->create_publisher<std_msgs::msg::String>(
      "rtt_ack", rclcpp::QoS(10).reliable());
  }

private:
  void callback_send(const std_msgs::msg::String::SharedPtr msg) {
    auto msg_ack = std_msgs::msg::String();
    msg_ack.data = "ackmsg num " + msg->data.substr(12);
    pub_ack_->publish(msg_ack);
    RCLCPP_INFO(this->get_logger(), "Received: [%s]", msg->data.c_str());
  }

  rclcpp::Subscription<std_msgs::msg::String>::SharedPtr sub_send_;
  rclcpp::Publisher<std_msgs::msg::String>::SharedPtr pub_ack_;
};

int main(int argc, char *argv[])
{
  rclcpp::init(argc, argv);
  auto node = std::make_shared<RTT_Receiver>();

  rclcpp::spin(node);
  rclcpp::shutdown();
  
  return 0;
}
