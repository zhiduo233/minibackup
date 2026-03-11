# 1. 选择基础镜像
FROM gcc:latest

# 2. 安装 CMake 和 Python3
# 加上 python3，可以在容器里跑你的单元测试
RUN apt-get update && apt-get install -y \
    cmake \
    python3 \
    && rm -rf /var/lib/apt/lists/*

# 3. 设置工作目录
WORKDIR /usr/src/minibackup

# 4. 复制所有文件
COPY . .

# 5. 构建项目
# 清理旧的 build (如果有的话)，然后重新构建
RUN rm -rf build && \
    mkdir build && \
    cd build && \
    cmake .. && \
    make

# 6. 方便测试
# 把编译好的 .so 和 可执行文件 复制到根目录，一进容器就能看到
RUN cp build/minibackup . && \
    cp build/*.so . || cp build/*.dll . || true

# 7. 设置环境变量，让 Python 能找到当前目录下的 .so
ENV LD_LIBRARY_PATH=/usr/src/minibackup

# 8. 默认运行 CLI 帮助
CMD ["./minibackup"]