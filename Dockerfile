FROM ubuntu:24.04

LABEL org.opencontainers.image.title="enprot"
LABEL org.opencontainers.image.description="Engyon Protected Text — confidentiality and provenance for text"
LABEL org.opencontainers.image.source="https://github.com/engyon/enprot"
LABEL org.opencontainers.image.licenses="BSD-2-Clause"

ARG TARGETARCH

# Install build dependencies for vendored-rnp + botan-src.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates \
      cmake \
      curl \
      git \
      make \
      python3 \
      g++ \
      pkg-config \
    && rm -rf /var/lib/apt/lists/*

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
