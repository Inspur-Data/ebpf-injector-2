# ⚠️ 关键修改：使用最新的 Ubuntu 24.04
# 这与 GitHub Actions 的最新宿主机环境保持一致 (GLIBC 2.39+)
FROM ubuntu:24.04

# 安装运行时必要的库
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libelf1 \
    zlib1g \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# 复制编译好的程序
# 确保你的 workflow 里编译生成的位置也是 src/bootstrap
COPY src/bootstrap /usr/sbin/bootstrap

# 启动命令
CMD ["/usr/sbin/bootstrap"]
