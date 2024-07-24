cmake_minimum_required(VERSION 3.28)
project(packetstorm CXX)

set(CMAKE_C_STANDARD 11)

add_executable(packetstorm main.cpp
        protos.h
        protos.cpp
)

target_link_libraries(packetstorm pcap)