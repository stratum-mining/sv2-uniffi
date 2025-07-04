#!/usr/bin/env bash

echo "Generating native binaries..."
cargo build --release

echo "Generating sv2.py..."
cargo run --bin uniffi-bindgen generate --library ../target/release/libsv2.dylib --language python --out-dir . --no-format

echo "Copying libraries libsv2.dylib..."
cp ../target/release/libsv2.dylib .