# syntax=docker/dockerfile:1.7

FROM ubuntu:24.04 AS builder

# ort's aarch64 binaries require glibc 2.38 or newer. Ubuntu 24.04 provides a
# compatible build environment; the Debian 13 runtime below has a newer glibc.
RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        build-essential \
        ca-certificates \
        clang \
        curl \
        libclang-dev \
        libssl-dev \
        pkg-config

RUN curl --proto '=https' --tlsv1.2 --fail --silent --show-error https://sh.rustup.rs | \
    sh -s -- -y --profile minimal --default-toolchain 1.88.0

ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /app

COPY Cargo.toml Cargo.lock build.rs ./
COPY migrations/ migrations/
COPY src/ src/

# Cache registries, compiled dependencies, and the downloaded static ONNX
# runtime outside image layers while copying only final binaries into /app/out.
RUN --mount=type=cache,id=polarizer-cargo-registry,target=/root/.cargo/registry,sharing=locked \
    --mount=type=cache,id=polarizer-cargo-git,target=/root/.cargo/git,sharing=locked \
    --mount=type=cache,id=polarizer-target,target=/app/target,sharing=locked \
    --mount=type=cache,id=polarizer-ort,target=/root/.cache/ort.pyke.io,sharing=locked \
    cargo build --locked --release --bins && \
    install -D -m 0755 target/release/polarizer /app/out/polarizer && \
    install -D -m 0755 target/release/polarizer-policy-worker /app/out/polarizer-policy-worker

FROM debian:trixie-slim AS runtime-tools

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends busybox-static tini && \
    install -D -m 0755 /bin/busybox /out/bin/busybox && \
    install -D -m 0755 /usr/bin/tini /out/bin/tini

# cc-debian13 supplies glibc, OpenSSL, libstdc++, zlib, zstd, and CA roots but
# no shell or package manager. Keep only the two small operational tools above.
FROM gcr.io/distroless/cc-debian13:nonroot AS runtime

WORKDIR /app

COPY --from=runtime-tools /out/bin/ /usr/bin/
COPY --from=builder --chown=65532:65532 /app/out/polarizer /app/polarizer
COPY --from=builder --chown=65532:65532 /app/out/polarizer-policy-worker /app/polarizer-policy-worker

ENV POLARIZER_POLICY_WORKER_BIN=/app/polarizer-policy-worker

# Deployments that enable local NSFW classification mount an approved model
# read-only and set NSFW_MODEL_PATH explicitly.
USER 65532:65532

EXPOSE 50051 9090
STOPSIGNAL SIGTERM

HEALTHCHECK --interval=10s --timeout=3s --start-period=40s --retries=6 \
    CMD ["/usr/bin/busybox", "wget", "-q", "-T", "2", "-O", "/dev/null", "http://127.0.0.1:9090/ready"]

ENTRYPOINT ["/usr/bin/tini", "--", "/app/polarizer"]
