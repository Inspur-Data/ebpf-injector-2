# ---- Stage 1: The Builder ----
FROM debian:bullseye-slim AS builder

ENV DEBIAN_FRONTEND=noninteractive

# 1. 安装构建工具
# 显式添加 ca-certificates 以确保 curl 能正确处理 https
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

# 2. 稳健的下载方式 (分步执行)
# -f: 遇到 404/500 错误时直接失败，不输出错误页面
# -L: 跟随重定向
# -o: 保存为文件，不使用管道，避免掩盖错误
RUN curl -f -L -o /tmp/btf.tar.xz https://github.com/aquasecurity/btfhub-archive/raw/main/ubuntu/20.04/x86_64/5.8.0-63-generic.btf.tar.xz

# 3. [...](asc_slot://start-slot-1)解压 BTF 文件
# 这里的 tar 会从刚才下载的文件中解压，并将内容输出到 vmlinux.btf
RUN tar -xJf /tmp/btf.tar.xz -O > /src/vmlinux.btf

# 4. 编译
RUN make build VMLINUX_BTF=/src/vmlinux.btf


# ---- Stage 2: The Final Image ----
FROM debian:bullseye-slim

COPY --from=builder /src/src/bootstrap /usr/sbin/bootstrap

CMD ["/usr/sbin/bootstrap"]
