cmake_minimum_required(VERSION 3.10)
project(minibackup)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(MINGW)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libgcc -static-libstdc++")
    set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} -static-libgcc -static-libstdc++ -static")
    set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -static-libgcc -static-libstdc++ -static")
endif()

include_directories(include)

# ==========================================
# 1. 生成核心动态库 (给 Python 用)
# ==========================================
add_library(core SHARED
        src/BackupEngine.cpp
        src/Bridge.cpp
        include/BackupEngine.h
        include/CRC32.h
)

# ==========================================
# 2. 生成命令行工具 (minibackup)
# ==========================================
# [修改点]：把 BackupEngine.cpp 也加到这里！
# 这样 exe 就自带核心逻辑，不需要去 dll 里找了，从而避开了 Windows 的导出问题。
add_executable(minibackup
        src/main.cpp
        src/BackupEngine.cpp
        include/BackupEngine.h
        include/CRC32.h
)

# [修改点]：去掉或者注释掉 target_link_libraries
# 因为我们已经把源码编进去了，不需要再链接 core 库了
# target_link_libraries(minibackup core)

# 设置 RPATH (Linux下有用，Windows下无视)
set_target_properties(minibackup PROPERTIES INSTALL_RPATH ".")