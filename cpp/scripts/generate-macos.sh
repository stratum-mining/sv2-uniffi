#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CPP_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
REPO_DIR="$(cd "$CPP_DIR/.." && pwd)"
BINDGEN_CPP="${UNIFFI_BINDGEN_CPP:-uniffi-bindgen-cpp}"

cd "$REPO_DIR"

echo "Generating native binaries..."
cargo build --release

echo "Generating C++ bindings..."
"$BINDGEN_CPP" --library "$REPO_DIR/target/release/libsv2.dylib" --out-dir "$CPP_DIR"

echo "Copying libraries libsv2.dylib..."
cp "$REPO_DIR/target/release/libsv2.dylib" "$CPP_DIR/"
