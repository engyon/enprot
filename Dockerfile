FROM ubuntu:24.04

LABEL org.opencontainers.image.title="enprot"
LABEL org.opencontainers.image.description="Engyon Protected Text — confidentiality and provenance for text"
LABEL org.opencontainers.image.source="https://github.com/engyon/enprot"
LABEL org.opencontainers.image.licenses="BSD-2-Clause"

ARG TARGETARCH
ARG BOTAN_VERSION=3.7.0

# Install build dependencies. zlib + bzip2 dev headers are needed by
# both Botan and librnp's transitive deps.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      cmake \
      curl \
      git \
      make \
      python3 \
      g++ \
      pkg-config \
      xz-utils \
      zlib1g-dev \
      libbz2-dev \
      libclang-dev \
    && rm -rf /var/lib/apt/lists/*

# Build Botan 3 from source — Ubuntu 24.04 only ships Botan 2.
RUN curl -LO https://botan.randombit.net/releases/Botan-${BOTAN_VERSION}.tar.xz && \
    tar xf Botan-${BOTAN_VERSION}.tar.xz && \
    cd Botan-${BOTAN_VERSION} && \
    python3 configure.py --prefix=/usr/local --build-targets=static && \
    make -j$(nproc) && \
    make install && \
    cd .. && \
    rm -rf Botan-${BOTAN_VERSION} Botan-${BOTAN_VERSION}.tar.xz

ENV PKG_CONFIG_PATH="/usr/local/lib/pkgconfig"

# Install Rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain stable
ENV PATH="/root/.cargo/bin:${PATH}"

# Build enprot from source (release with vendored deps)
WORKDIR /build
COPY . .
RUN cargo build --release --features vendored-rnp && \
    cp target/release/enprot /usr/local/bin/enprot && \
    cargo clean && \
    rm -rf /build

# Verify
RUN enprot --version

WORKDIR /work
ENTRYPOINT ["enprot"]
