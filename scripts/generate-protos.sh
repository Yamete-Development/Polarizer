#!/usr/bin/env bash
set -euo pipefail

repo_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cargo run --manifest-path "$repo_dir/tools/proto-gen/Cargo.toml"
cargo fmt --manifest-path "$repo_dir/Cargo.toml"
