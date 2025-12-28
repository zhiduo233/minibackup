cmake_minimum_required(VERSION 3.10)
project(minibackup)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

include_directories(include)

# ==========================================
# 1. 生成核心动态库 (libcore.so)
# ==========================================
# SHARED 表示生成动态库
add_library(core SHARED
        src/BackupEngine.cpp
        src/Bridge.cpp    # 把接口层也编进去
        include/BackupEngine.h
        include/CRC32.h
)

# ==========================================
# 2. 生成命令行工具 (minibackup)
# ==========================================
add_executable(minibackup
        src/main.cpp
)

# 让可执行文件链接到动态库
# 这样 main.cpp 就能调用 BackupEngine 了，虽然 main 用的是 C++ 接口，但库里也有 C 接口
target_link_libraries(minibackup core)

# Docker/Linux 环境设置 RPATH
# 确保 ./minibackup 运行时能找到 libcore.so，而不需要设置环境变量
set_target_properties(minibackup PROPERTIES INSTALL_RPATH ".")