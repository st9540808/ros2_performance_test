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
#include <unistd.h>

#include "rclcpp/rclcpp.hpp"
#include "std_msgs/msg/string.hpp"

using namespace std::chrono_literals;

class Talker : public rclcpp::Node {
public:
  Talker()
  : Node("talker"), count_(0) {
    pub_ = this->create_publisher<std_msgs::msg::String>("chatter", rclcpp::QoS(10).reliable());
    timerPtr_ = this->create_wall_timer(
      10ms, std::bind(&Talker::callback, this));
    timerPtr_->cancel();
  }

  void callback(void) {
    char str[7];
    this->timerPtr_->cancel();
    std::snprintf(str, 7, "%05d", this->count_++);
    auto message = std_msgs::msg::String();
    
    std::string base;
    message.data = "hello world " + std::string(str);
    
    // RCLCPP_INFO(this->get_logger(), "Publishing: '%s'", message.data.c_str());
    this->pub_->publish(message);
    this->timerPtr_->reset();
  }
 
  int count_;
  rclcpp::TimerBase::SharedPtr timerPtr_;
  rclcpp::Publisher<std_msgs::msg::String>::SharedPtr pub_;
};

int main(int argc, char *argv[])
{
  rclcpp::init(argc, argv);
  auto node = std::make_shared<Talker>();

  // for (int i = 0; i < 40; i++) {
  //   RCLCPP_INFO(node->get_logger(), "count_subscribers: '%d'",
  //               node->count_subscribers("/chatter"));
  //   rclcpp::sleep_for(50ms);
  // }
  // sleep(2);
  // while (node->count_subscribers("/chatter") < 1)
  //   rclcpp::sleep_for(50ms);

  // rclcpp::spin(node);
  char str[10];
  for (int i = 0; i < 10000 && rclcpp::ok(); i++) {
    auto message = std_msgs::msg::String();
    std::snprintf(str, 7, "%06d", i);
    message.data = "hello world " + std::string(str);
    RCLCPP_INFO(node->get_logger(), "Publishing: '%s'", message.data.c_str());
    node->pub_->publish(message);
    rclcpp::sleep_for(500ms);
  }

  rclcpp::shutdown();
}