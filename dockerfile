# ---- Stage 1: Builder ----
FROM debian:bullseye-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

# 1. 安装依赖
# gcc-multilib: 解决 "gnu/stubs-32.h not found" 的关键
# curl, xz-utils: 用于下载 BTF
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    pkg-config \
    make \
    clang \
    llvm \
    libelf1 \
    libelf-dev \
    zlib1g-dev \
    git \
    curl \
    xz-utils \
    gcc-multilib

WORKDIR /src
COPY . .

# 2. 下载 BTF 文件 (使用 raw 链接)
# 这是 Docker 编译 eBPF 必须的一步，因为容器里没有内核
RUN curl -f -L -o /tmp/btf.tar.xz https://github.com/aquasecurity/btfhub-archive/raw/main/ubuntu/20.04/x86_64/5.8.0-63-generic.btf.tar.xz && \
    tar -xJf /tmp/btf.tar.xz -O > /src/vmlinux.btf

# 3. 编译
# 直接进入 src 目录编译，指定 BTF 文件路径
# 这样更直接，不容易出错
WORKDIR /src/src
RUN make VMLINUX_BTF=/src/vmlinux.btf


# ---- Stage 2: Final Image ----
FROM debian:bullseye-slim

# 安装运行时依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libelf1 \
    zlib1g && \
    rm -rf /var/lib/apt/lists/*

# 复制编译好的程序
# 注意：因为我们在 src 目录下执行的 make，所以二进制文件就在 /src/src/bootstrap
COPY --from=builder /src/src/bootstrap /usr/sbin/bootstrap

CMD ["/usr/sbin/bootstrap"]
