# ---- Stage 1: The Builder ----
# 1. 切换到 Ubuntu 22.04，获取更新的 Clang 14 和工具链
FROM ubuntu:22.04 AS builder

# 避免安装过程中的交互提示
ENV DEBIAN_FRONTEND=noninteractive

# 2. 安装依赖
# Ubuntu 22.04 的软件源里工具更新，对 BPF 支持更好
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
    ca-certificates \
    g++-multilib

WORKDIR /src
COPY . .

# 3. 下载 BTF 文件 (使用我们验证过的 raw 链接)
RUN curl -f -L -o /tmp/btf.tar.xz https://github.com/aquasecurity/btfhub-archive/raw/main/ubuntu/20.04/x86_64/5.8.0-63-generic.btf.tar.xz && \
    tar -xJf /tmp/btf.tar.xz -O > /src/vmlinux.btf

# 4. 编译
# 加上 V=1 打印详细日志，万一出错方便排查
# 指定 clang 编译器，确保使用的是我们安装的新版本
RUN make build VMLINUX_BTF=/src/vmlinux.btf V=1 CLANG=clang


# ---- Stage 2: The Final Image ----
# 运行时也使用 Ubuntu 22.04，保持 GLIBC 版本一致
FROM ubuntu:22.04

# 安装运行时必须的库 (libelf, zlib)
# 这一步很重要，否则运行程序可能会报 "libelf.so.1 not found"
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    libelf1 \
    zlib1g && \
    rm -rf /var/lib/apt/lists/*

# 复制编译好的程序
COPY --from=builder /src/src/bootstrap /usr/sbin/bootstrap

CMD ["/usr/sbin/bootstrap"]
