cmake_minimum_required(VERSION 3.24)
project(Atam4 C)

set(CMAKE_C_STANDARD 11)

include_directories(.)

add_executable(Atam4
        "elf64 (1).h"
        hw4.c)
