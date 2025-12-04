# 直接使用和 GitHub Actions 宿主机一致的系统
# 这样编译出来的程序绝对兼容
FROM ubuntu:22.04

# 安装运行时必要的库
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libelf1 \
    zlib1g \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# 这里的路径要对应 Workflow 中编译生成的位置
# 因为我们在 src 目录下执行 make，生成的文件在 src/bootstrap
COPY src/bootstrap /usr/sbin/bootstrap

CMD ["/usr/sbin/bootstrap"]
