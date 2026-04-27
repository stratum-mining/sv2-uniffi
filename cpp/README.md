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

## Generated naming

`uniffi-bindgen-cpp` uses its default Google enum style, so generated enum variants are prefixed with `k`.
For rich enums, those variants are nested wrapper types inside a `std::variant`, for example `sv2::Sv2Message::kOpenMiningChannelError`.

## Build tests and examples

The C++ tests and examples are built with CMake after the bindings have been generated.

```shell
cmake -S . -B build
cmake --build build
```

To build only the tests:

```shell
cmake -S . -B build -DSV2CPP_BUILD_TESTS=ON -DSV2CPP_BUILD_EXAMPLES=OFF
cmake --build build
```

To build only the examples:

```shell
cmake -S . -B build -DSV2CPP_BUILD_TESTS=OFF -DSV2CPP_BUILD_EXAMPLES=ON
cmake --build build
```

## Run tests

Run all C++ tests with CTest:

```shell
ctest --test-dir build --output-on-failure
```

Or run individual test binaries directly from the build directory, for example:

```shell
./build/sv2cpp_test_import
./build/sv2cpp_test_handshake
./build/sv2cpp_test_encoding_decoding
./build/sv2cpp_test_extranonce_allocator
```

## Run examples

Example binaries are generated with the `sv2cpp_example_` prefix:

```shell
./build/sv2cpp_example_extranonce_allocator_example
./build/sv2cpp_example_bootstrap_extended_channel_server_example
./build/sv2cpp_example_bootstrap_standard_channel_server_example
./build/sv2cpp_example_template_distribution_example
./build/sv2cpp_example_server_example
./build/sv2cpp_example_client_example
```

Run `sv2cpp_example_server_example` in one terminal, then run `sv2cpp_example_client_example` in another terminal to see a complete Noise_NX handshake, `SetupConnection`, and `SetupConnectionSuccess` flow.
