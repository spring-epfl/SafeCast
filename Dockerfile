# Container for reproducing the benchmarks and figures: see "Docker (alternative)" in the README.

# 1.87: the toolchain the benchmark results were produced with
FROM rust:1.87-slim-bookworm

# make/cc to compile libsrtp, libclang to generate its Rust bindings from the
# C headers, OpenSSL, python for the notebook
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential \
        clang \
        libclang-dev \
        pkg-config \
        libssl-dev \
        python3 \
        python3-pip \
    && rm -rf /var/lib/apt/lists/*

# all subsequent commands run from, and the repo is copied into, this directory
WORKDIR /safecast

# copying the requirements file for the notebook's Python deps
COPY requirements.txt .

# installing the notebook's Python deps
RUN pip3 install --no-cache-dir --break-system-packages -r requirements.txt

# copying the rest of the repo into the image
COPY . .

# prebuilding all benchmarks so `docker run` goes straight to measuring
RUN cargo bench --package safecast-core --no-run

# running the full benchmark + figure regeneration pipeline
ENTRYPOINT ["./REPRODUCE.sh"]
