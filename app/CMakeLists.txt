cmake_minimum_required(VERSION 3.13)  # CMake version check
project(simple_example)               # Create project "simple_example"
set(CMAKE_CXX_STANDARD 17)            # Enable c++14 standard

# Add main.cpp file of project root directory as source file
set(SOURCE_FILES server/start.cpp user/start-user.cpp)

set (CMAKE_C_COMPILER /usr/local/bin/gcc-8)
set (CMAKE_CXX_COMPILER /usr/local/bin/g++-8)

#include deps
add_library(utils SHARED ./utils.h)

# Add executable target with source files listed in SOURCE_FILES variable
add_executable(start-server ${SOURCE_FILES})
target_link_libraries(start-server utils)
add_executable(start-user ${SOURCE_FILES})
target_link_libraries(start-user utils)