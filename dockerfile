# ---- Stage 1: The Builder ----
# We use the same base image that we will use for the final runtime environment.
FROM debian:bullseye-slim AS builder

# Set an environment variable to avoid interactive prompts during package installation
ENV DEBIAN_FRONTEND=noninteractive

# Install all build dependencies, including the multi-arch support library
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
    g++-multilib # <--- 关键：添加这个包来解决 stubs-32.h 缺失的问题

# Copy the entire source code into the builder stage
WORKDIR /src
COPY . .

# Build the application. The executable will be created inside this stage.
RUN make build


# ---- Stage 2: The Final Image ----
# Start fresh from the same slim base image
FROM debian:bullseye-slim

# Copy the compiled binary from the 'builder' stage to the final image.
COPY --from=builder /src/src/bootstrap /usr/sbin/bootstrap

# This is the command that will run when the container starts.
CMD ["/usr/sbin/bootstrap"]
