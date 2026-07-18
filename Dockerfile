# ── Builder stage ────────────────────────────────────────────────────────────
FROM ubuntu:24.04 AS builder

# ort v2.0 pre-compiled binaries for aarch64 require glibc 2.38+. 
# We use Ubuntu 24.04 (glibc 2.39) to satisfy both linking and runtime requirements.
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    curl \
    ca-certificates \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Install Rust 1.88 (required by image/ort)
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y --default-toolchain 1.88.0
ENV PATH="/root/.cargo/bin:${PATH}"

WORKDIR /app

# Build from committed generated Protobuf code. The embedded SQLx migrator
# requires the migrations directory to be present at compile time.
COPY Cargo.toml Cargo.lock build.rs ./
COPY migrations/ migrations/
COPY src/ src/
RUN cargo build --release --bins

# ort v2.0 dynamically links libonnxruntime.so and downloads it to the global cache.
# We need to find it and move it to a predictable location.
RUN mkdir -p /app/out-libs && \
    find /root/.cache/ort.pyke.io target/ -name "libonnxruntime.so*" -exec cp {} /app/out-libs/ \;

# ── Runtime stage ────────────────────────────────────────────────────────────
FROM ubuntu:24.04

# Create a non-root user
RUN groupadd -r nonroot && useradd -r -g nonroot nonroot

# Install required certificates for outbound HTTPS and curl for the container
# readiness probe. A partially started Polarizer must not be considered healthy.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy the API service and the isolated Luau worker. Both are required for a
# ready Polarizer instance.
COPY --from=builder /app/target/release/polarizer /app/polarizer
COPY --from=builder /app/target/release/polarizer-policy-worker /app/polarizer-policy-worker

# Copy the ONNX Runtime dynamic libraries
COPY --from=builder /app/out-libs/ /usr/lib/

# Set the library path so the OS can find libonnxruntime.so
ENV LD_LIBRARY_PATH=/usr/lib
ENV POLARIZER_POLICY_WORKER_BIN=/app/polarizer-policy-worker

# Local NSFW classification is an optional check. Deployments that enable it
# mount an approved model read-only and set NSFW_MODEL_PATH explicitly.

USER nonroot

EXPOSE 50051 9090

HEALTHCHECK --interval=10s --timeout=3s --start-period=40s --retries=6 \
    CMD ["curl", "--fail", "--silent", "--show-error", "--max-time", "2", "http://127.0.0.1:9090/ready"]

ENTRYPOINT ["/app/polarizer"]
