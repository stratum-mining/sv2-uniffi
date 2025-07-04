#!/usr/bin/env bash

echo "Generating native binaries..."
cargo build --release

echo "Generating sv2.py..."
cargo run --bin uniffi-bindgen generate --library ../target/release/libsv2.so --language python --out-dir . --no-format

echo "Copying libraries libsv2.so..."
cp ../target/release/libsv2.so .