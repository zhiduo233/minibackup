# 1. 选择基础镜像：使用官方的 GCC 编译器环境
FROM gcc:latest

# 2. 安装 CMake (GCC 镜像默认可能没有 cmake，或者版本较老，保险起见安装一下)
RUN apt-get update && apt-get install -y cmake

# 3. 设置容器内的工作目录 (就像是在容器里新建了一个文件夹)
WORKDIR /usr/src/minizip

# 4. 把你当前目录下的所有文件，复制到容器里
COPY . .

# 5. 开始构建
# 创建 build 文件夹 -> 进入 -> 运行 cmake -> 运行 make
RUN mkdir build && cd build && cmake .. && make

# 6. 设置容器启动时的默认命令
# 运行容器时，自动执行编译好的 minizip 程序
CMD ["./build/minizip"]