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
class Listener : public rclcpp::Node
{
public:
  Listener() : Node("listener") {
    sub_ = this->create_subscription<std_msgs::msg::String>(
      "chatter",
      rclcpp::QoS(10).reliable(),
      std::bind(&Listener::callback, this, std::placeholders::_1)
      );
  }

private:
  void callback(const std_msgs::msg::String::SharedPtr msg) {
    RCLCPP_INFO(this->get_logger(), "I heard: [%s]", msg->data.c_str());
  }

  rclcpp::Subscription<std_msgs::msg::String>::SharedPtr sub_;
};

int main(int argc, char *argv[])
{
  rclcpp::init(argc, argv);
  auto node = std::make_shared<Listener>();
  
  // auto event = node->get_graph_event();
  // RCLCPP_INFO(node->get_logger(), "entering wait_for_graph_change");
  // node->wait_for_graph_change(event, 30s);
  // RCLCPP_INFO(node->get_logger(), "return from wait_for_graph_change");
  // event->check_and_clear();

  // RCLCPP_INFO(node->get_logger(), "entering wait_for_graph_change");
  // node->wait_for_graph_change(event, 30s);
  // RCLCPP_INFO(node->get_logger(), "return from wait_for_graph_change");

  // auto map = node->get_topic_names_and_types();
  // for (auto [k, v] : map) {
  //   std::cout << k << ": ";
  //   for (auto str : v) std::cout << "  " << str << std::endl;
  // }

  rclcpp::spin(node);
  rclcpp::shutdown();
  
  return 0;
}
