# sv2cpp

C++ bindings for the [Stratum V2 Reference Implementation](https://github.com/stratum-mining/stratum).

The bindings are generated with [`uniffi-bindgen-cpp`](https://github.com/NordSecurity/uniffi-bindgen-cpp). C++20 is required.

## Install generator

```shell
cargo install uniffi-bindgen-cpp --git https://github.com/NordSecurity/uniffi-bindgen-cpp --tag v0.8.1+v0.29.4
```

## Build locally

```shell
# Generate the bindings
bash ./scripts/generate-linux.sh
## OR
bash ./scripts/generate-macos.sh
```

Generated files are written into this directory and are intentionally ignored by git:

- `sv2.hpp`
- `sv2.cpp`
- `sv2_scaffolding.hpp`
- `libsv2.so` or `libsv2.dylib`
