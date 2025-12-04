# ---- Stage 1: The Builder ----
FROM debian:bullseye-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

# 1. 安装依赖
# 必须包含 curl, xz-utils (下载解压) 和 g++-multilib (解决 stubs-32.h)
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

# 2. 关键修复：使用 'raw' 链接下载 BTF 文件
# ❌ 错误链接: .../blob/main/... (这是网页)
# ✅ 正确链接: .../raw/main/...  (这才是文件)
RUN curl -L https://github.com/aquasecurity/btfhub-archive/raw/main/ubuntu/20.04/x86_64/5.8.0-63-generic.btf.tar.xz | \
    tar xJ -O > /src/vmlinux.btf

# 3. 使用下载的 BTF 文件进行编译
RUN make build VMLINUX_BTF=/src/vmlinux.btf


# ---- Stage 2: The Final Image ----
FROM debian:bullseye-slim

# 复制编译好的二进制文件
COPY --from=builder /src/src/bootstrap /usr/sbin/bootstrap

CMD ["/usr/sbin/bootstrap"]
