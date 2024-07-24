cmake_minimum_required(VERSION 3.28)
project(packetstorm C CXX)

set(CMAKE_C_STANDARD 11)

add_executable(packetstorm main.c
        protos.h
        protos.c
        hash_table.cpp
        hash_table.h)

target_link_libraries(packetstorm pcap)