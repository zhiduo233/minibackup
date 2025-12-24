cmake_minimum_required(VERSION 3.10)

# 1. 项目名称
project(minizip)

# 2. 设置 C++ 标准 (C++17 是目前课程作业的最佳甜点位)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# 3. 包含头文件目录
include_directories(include)

# 4. 生成可执行文件
# 告诉 CLion：把 src/main.cpp 编译成一个叫 minizip 的程序
add_executable(minizip
        src/main.cpp
)