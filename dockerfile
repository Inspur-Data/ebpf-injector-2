# ---- Stage 1: The Builder ----
FROM debian:bullseye-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

# 1. 安装基础构建工具，包括 curl 和 xz-utils，以及修复 stubs-32.h 错误的 g++-multilib
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
    g++-multilib

WORKDIR /src
COPY . .

# 2. 关键步骤：手动下载一个通用的 vmlinux BTF 文件
# 因为 Docker 构建环境里没有 /sys/kernel/btf/vmlinux
# 我们使用 BTFHub 提供的 Ubuntu 22.04 (Kernel 5.15) 的 BTF 文件作为编译基准
RUN curl -L https://github.com/aquasecurity/btfhub-archive/blob/main/ubuntu/20.04/x86_64/5.8.0-63-generic.btf.tar.xz | \
    tar xJ -O > /src/vmlinux.btf

# 3. 编译时指定 VMLINUX_BTF 路径
# 这样 bpftool 就会用我们下载的文件来生成 vmlinux.h，而不会去报错找不到文件
RUN make build VMLINUX_BTF=/src/vmlinux.btf


# ---- Stage 2: The Final Image ----
FROM debian:bullseye-slim

# 复制编译好的程序到标准目录
COPY --from=builder /src/src/bootstrap /usr/sbin/bootstrap

CMD ["/usr/sbin/bootstrap"]
