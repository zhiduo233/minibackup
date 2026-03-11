cmake_minimum_required(VERSION 3.10)
project(minibackup)

# 必须开启 C++17 (为了 std::filesystem)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# [针对 Windows MinGW 的配置]
# 静态链接标准库，防止生成的 exe 只有几 KB 且无法运行
if(MINGW)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++ -static")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++ -static")
endif()

include_directories(include)

# ==========================================
# 1. 生成核心动态库 (给 Python GUI 用)
# ==========================================
add_library(core SHARED
        src/BackupEngine.cpp
        src/Bridge.cpp
        src/Huffman.cpp
)
# 显式开启位置无关代码 (fPIC)，这对 Linux .so 是必须的
set_property(TARGET core PROPERTY POSITION_INDEPENDENT_CODE ON)

# ==========================================
# 2. 生成命令行工具 (minibackup CLI)
# ==========================================
# 把 BackupEngine.cpp 编进去，让 exe 独立运行
add_executable(minibackup
        src/main.cpp
        src/BackupEngine.cpp
        src/Huffman.cpp
)

# Linux 下通常需要链接 pthread 库，防止链接错误
if(UNIX)
    target_link_libraries(minibackup pthread)
endif()

# 设置输出提示
message(STATUS "Build config ready. Run 'make' to compile.")