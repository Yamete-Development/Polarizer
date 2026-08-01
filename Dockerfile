# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.88.0

# ---------------------------------------------------------------------------
# Shared Rust build environment
# ---------------------------------------------------------------------------
FROM ubuntu:24.04 AS rust-base

ARG RUST_VERSION

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

RUN curl --proto '=https' \
         --tlsv1.2 \
         --fail \
         --silent \
         --show-error \
         https://sh.rustup.rs | \
    sh -s -- \
        -y \
        --profile minimal \
        --default-toolchain "${RUST_VERSION}"

ENV PATH="/root/.cargo/bin:${PATH}"
ENV CARGO_NET_GIT_FETCH_WITH_CLI=true

# cargo-chef itself is cached as an ordinary Docker layer.
RUN --mount=type=cache,id=polarizer-cargo-registry,target=/root/.cargo/registry,sharing=locked \
    --mount=type=cache,id=polarizer-cargo-git,target=/root/.cargo/git,sharing=locked \
    cargo install cargo-chef --locked

WORKDIR /app


# ---------------------------------------------------------------------------
# Generate dependency recipe
# ---------------------------------------------------------------------------
FROM rust-base AS planner

COPY Cargo.toml Cargo.lock build.rs ./
COPY migrations/ migrations/
COPY src/ src/

RUN cargo chef prepare --recipe-path recipe.json


# ---------------------------------------------------------------------------
# Compile dependencies separately
# ---------------------------------------------------------------------------
FROM rust-base AS builder

COPY --from=planner /app/recipe.json recipe.json

RUN --mount=type=cache,id=polarizer-cargo-registry,target=/root/.cargo/registry,sharing=locked \
    --mount=type=cache,id=polarizer-cargo-git,target=/root/.cargo/git,sharing=locked \
    --mount=type=cache,id=polarizer-target,target=/app/target,sharing=locked \
    --mount=type=cache,id=polarizer-ort,target=/root/.cache/ort.pyke.io,sharing=locked \
    cargo chef cook \
        --locked \
        --release \
        --recipe-path recipe.json

# Source changes invalidate only this section, not the dependency layer above.
COPY Cargo.toml Cargo.lock build.rs ./
COPY migrations/ migrations/
COPY src/ src/

RUN --mount=type=cache,id=polarizer-cargo-registry,target=/root/.cargo/registry,sharing=locked \
    --mount=type=cache,id=polarizer-cargo-git,target=/root/.cargo/git,sharing=locked \
    --mount=type=cache,id=polarizer-target,target=/app/target,sharing=locked \
    --mount=type=cache,id=polarizer-ort,target=/root/.cache/ort.pyke.io,sharing=locked \
    cargo build \
        --locked \
        --release \
        --bin polarizer \
        --bin polarizer-policy-worker && \
    install -D -m 0755 \
        target/release/polarizer \
        /app/out/polarizer && \
    install -D -m 0755 \
        target/release/polarizer-policy-worker \
        /app/out/polarizer-policy-worker


# ---------------------------------------------------------------------------
# Extract runtime tools
# ---------------------------------------------------------------------------
FROM debian:trixie-slim AS runtime-tools

RUN --mount=type=cache,target=/var/cache/apt,sharing=locked \
    --mount=type=cache,target=/var/lib/apt,sharing=locked \
    apt-get update && \
    apt-get install -y --no-install-recommends \
        busybox-static \
        tini && \
    install -D -m 0755 /bin/busybox /out/bin/busybox && \
    install -D -m 0755 /usr/bin/tini /out/bin/tini


# ---------------------------------------------------------------------------
# Runtime
# ---------------------------------------------------------------------------
FROM gcr.io/distroless/cc-debian13:nonroot AS runtime

WORKDIR /app

COPY --from=runtime-tools /out/bin/ /usr/bin/
COPY --from=builder --chown=65532:65532 \
    /app/out/polarizer \
    /app/polarizer
COPY --from=builder --chown=65532:65532 \
    /app/out/polarizer-policy-worker \
    /app/polarizer-policy-worker

ENV POLARIZER_POLICY_WORKER_BIN=/app/polarizer-policy-worker

USER 65532:65532

EXPOSE 50051 9090
STOPSIGNAL SIGTERM

HEALTHCHECK \
    --interval=10s \
    --timeout=3s \
    --start-period=40s \
    --retries=6 \
    CMD ["/usr/bin/busybox", "wget", "-q", "-T", "2", "-O", "/dev/null", "http://127.0.0.1:9090/ready"]

ENTRYPOINT ["/usr/bin/tini", "--", "/app/polarizer"]
