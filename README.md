# MiniBackup - C++ 数据备份

> 课程设计项目 | 基于 C++17 实现 | 支持加密与打包

## 1. 项目简介 (Project Overview)
本项目实现了一款具备工业级特性的数据备份软件。采用 **C++17** 编写核心逻辑，通过 **CMake** 进行构建，并封装为 **动态链接库 (Shared Library)** 以支持 Python GUI 调用。

###  项目特性与任务清单 (Feature To-Do List)

#### 1. 核心基础功能 (已完成)
> 对应作业基础分 (40分)
- [x] **数据备份**：支持递归扫描目录树，完整复制文件数据。
- [x] **数据还原**：能够将备份数据恢复到指定路径。
- [x] **备份验证**：集成 CRC32 校验算法，支持检测文件损坏与容错处理。(额外算分)
- [x] **底层架构**：
    - [x] 核心逻辑封装为动态库 (`libcore.so` / `core.dll`)。
    - [x] 实现 C-ABI 接口导出，支持跨语言调用。
    - [x] Docker 环境标准化构建。

#### 2. 已完成的扩展功能 (当前得分项)
> 对应扩展分 (~30-40分)
- [x] **打包解包** (+10分)：
    - [x] 实现自定义 `.pck` 二进制文件格式。
    - [x] 支持多文件合并存储。
- [x] **加密解密** (+20分)：
    - [x] **RC4 流密码**：实现标准流式加密算法。
    - [x] **XOR 混淆**：实现基础加密算法。
    - [x] 支持解包时自动识别加密模式。
- [x] **特殊文件支持** (+10分 | 不确定，因为只支持了这一个特殊文件，这个不关键)：
    - [x] **软链接 (Symlink)**：支持 Linux 符号链接的正确存储与恢复（非复制内容）。

#### 3. 待开发/可选扩展功能 (Pending)
> 可认领任务，建议优先完成 GUI

**🔴 高优先级 (High Priority)**
- [x] **图形界面 (GUI)** (+10分)：
    - [x] 基于 Python (Tkinter/PyQt) 对接动态库接口。
    - [x] 实现目录选择、一键备份/还原/打包的可视化操作。

**🟡 中优先级 (性价比高，建议做)**
- [x] **元数据支持** (+10分)：
    - [x] 备份时记录文件权限 (`chmod`) 和修改时间 (`mtime`)。
    - [x] 还原时恢复上述元数据。
- [x] **自定义备份** (+18分)：
    - [x] 实现文件筛选器（如：只备份 `.cpp`，或跳过 `.tmp`）。

**⚪ 低优先级 (视时间充裕度而定)**
- [x] **压缩解压** (+10分)：实现 RLE 或 LZ77 算法以减小包体积。
- [ ] **定时备份** (+10分)：基于简单的 Timer 实现周期性调用。
- [ ] **实时备份** (+15分)：监听文件系统变动 (inotify)。

## 2. 项目结构 (Structure)

```text
minibackup/
├── include/
│   ├── BackupEngine.h    # 核心引擎接口
│   └── CRC32.h           # CRC 校验工具
├── src/
│   ├── main.cpp          # 命令行入口 (CLI)
│   ├── BackupEngine.cpp  # 业务逻辑实现 (RC4/XOR/Pack都在这里)
│   └── Bridge.cpp        # C-API 接口层 (暴露给 Python 使用)
├── CMakeLists.txt        # 构建脚本 (生成 libcore.so 和 minibackup)
├── Dockerfile            # 标准化编译环境
└── README.md             # 说明文档
```

## 3. 开始

```
 1. 进入项目目录
`cd minibackup`

 2. 创建构建目录
`mkdir build && cd build`

 3. 生成 Makefile
`cmake ..`

 4. 编译
`make`

 编译完成后，build 目录下会生成：
 - minibackup (可执行文件，用于命令行测试)
 - libcore.so (动态库，用于 Python GUI)
```

### 1. 基础备份与恢复

##### 备份目录 A 到 B (镜像模式)
```./minibackup backup ./source_dir ./backup_dir```

##### 恢复数据
```./minibackup restore ./backup_dir ./restore_dir```

### 2. 高级打包 (Pack)
   支持加密、压缩和过滤器。

语法: pack <src> <pck_file> [options]

示例:

```
简单打包
`./minibackup pack ./data output.pck`

 加密(RC4) + 压缩(RLE) + 密码
./minibackup pack ./data secret.pck -rc4 -rle -pwd "mypassword"

 [高级筛选]：只打包最近 3 天修改的、小于 10MB 的 .txt 文件
./minibackup pack ./data filter.pck -name ".txt" -max 10485760 -days 3
```

参数说明:

-rc4 / -xor: 启用加密算法。

-rle: 启用压缩。

-pwd <str>: 设置密码。

-name <str> / -path <str>: 按名称或路径过滤。

-min <bytes> / -max <bytes>: 按大小过滤。

-days <n>: 仅备份最近 N 天修改的文件。

### 3. 高级解包 (Unpack)
语法: unpack <pck_file> <dest_dir> [pwd]

# 解包 (如有密码需提供)
```
./minibackup unpack secret.pck ./output_dir -pwd "mypassword"
```

## 4. 演示：软连接和元数据之权限

```
docker run -it --rm --privileged -v "$(pwd):/usr/src/minibackup" minibackup_img /bin/bash
```

```
rm -rf build && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make
```

```
ls -lR demo_linux_src
```

```
./build/minibackup pack demo_linux_src demo_linux.pck -rle
```

```
./build/minibackup unpack demo_linux.pck demo_linux_restore
```

```
python3 -c "import socket; s = socket.socket(socket.AF_UNIX); s.bind('demo_linux_src/my_socket')"
```