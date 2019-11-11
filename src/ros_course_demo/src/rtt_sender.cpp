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

#include <chrono>
#include <cstdio>
#include <memory>
#include <string>
#include <utility>
#include <vector>
#include <mutex>
#include <condition_variable>
#include <unistd.h>

#include "rclcpp/rclcpp.hpp"
#include "std_msgs/msg/string.hpp"

using namespace std::chrono_literals;
std::condition_variable cond;
std::mutex mtx;
int acked = 0;

class RTT_Sender : public rclcpp::Node {
public:
  RTT_Sender()
  : Node("rtt_sender"), count_(0), ulock_(mtx, std::defer_lock) {
    pub_send_ = this->create_publisher<std_msgs::msg::String>("rtt_send", rclcpp::QoS(10).reliable());
    sub_ack_ = this->create_subscription<std_msgs::msg::String>(
      "rtt_ack", rclcpp::QoS(10).reliable(),
      std::bind(&RTT_Sender::callback_ack, this, std::placeholders::_1));
  }

  void callback_ack(const std_msgs::msg::String::SharedPtr msg) {
    RCLCPP_INFO(this->get_logger(), "Received: '%s'\n", msg->data.c_str());
    ulock_.lock();
    acked = 1;
    ulock_.unlock();
    cond.notify_one();
  }
 
  int count_;
  rclcpp::Publisher<std_msgs::msg::String>::SharedPtr pub_send_;
  rclcpp::Subscription<std_msgs::msg::String>::SharedPtr sub_ack_;
  std::unique_lock<std::mutex> ulock_;
};

int main(int argc, char *argv[])
{
  char str[10];
  
  rclcpp::init(argc, argv);
  auto node = std::make_shared<RTT_Sender>();
  std::unique_lock<std::mutex> ulock(mtx, std::defer_lock);

  while (node->count_subscribers("/rtt_send") < 1
         || node->count_subscribers("/rtt_ack") < 1)
    rclcpp::sleep_for(50ms);

  std::thread ack_thread(
    [=](std::shared_ptr<RTT_Sender> node) {
      rclcpp::spin(node);
      return 0;
    }, node);
  
  for (int i = 0; i < 10000 && rclcpp::ok(); i++) {
    auto msg = std_msgs::msg::String();
    
    std::snprintf(str, 7, "%06d", i);
    msg.data = "hello world " + std::string(str);  
    RCLCPP_INFO(node->get_logger(), "Publishing: '%s'", msg.data.c_str());
    node->pub_send_->publish(msg);
    
    ulock.lock();
    cond.wait(ulock, [](){ return acked != 0; });
    ulock.unlock();
    
    ulock.lock();
    acked = 0;
    ulock.unlock();
    rclcpp::sleep_for(500ms);
  }

  ack_thread.join();
  rclcpp::shutdown();
  return 0;
}