# Building and Testing the Rust Crate

The `opendht` crate links to the native OpenDHT C library. Cargo does not build
or bundle that library. Install Rust and the native dependencies described in
the [OpenDHT build guide](../BUILD.md).

## Install the Native Library

From the root of an OpenDHT source checkout, enable the C bindings:

```sh
cmake -S . -B build-bindings -DOPENDHT_C=ON -DBUILD_TESTING=ON
cmake --build build-bindings
ctest --test-dir build-bindings -R test_c --output-on-failure
cmake --install build-bindings
```

Installation may require administrator privileges, depending on the install
prefix. Set `CMAKE_INSTALL_PREFIX` when configuring to choose another location.
The linker and runtime loader must be able to find the installed libraries.
Applications can then depend on `opendht` from crates.io as shown in the
[README](README.md).

## Use an Uninstalled Native Build

You can use the native build directly by setting its library search paths.
For example, from the repository root on macOS:

```sh
export LIBRARY_PATH="$PWD/build-bindings${LIBRARY_PATH:+:$LIBRARY_PATH}"
export DYLD_LIBRARY_PATH="$PWD/build-bindings${DYLD_LIBRARY_PATH:+:$DYLD_LIBRARY_PATH}"
export RUSTFLAGS="-L native=$PWD/build-bindings"
cargo test --manifest-path rust/Cargo.toml --all-targets
```

On Linux use `LD_LIBRARY_PATH` instead of `DYLD_LIBRARY_PATH`; on Windows add
the native DLL directory to `PATH`. For an application outside this checkout,
use absolute paths to the native build and run Cargo in the application directory.

When linking an AddressSanitizer native build, use the same compiler runtime.
For example, with Clang:

```sh
export RUSTFLAGS="-L native=$PWD/build-bindings -C linker=clang -C link-arg=-fsanitize=address"
```

## Build and Test the Crate

With the native library available, run from the `rust` directory:

```sh
cargo build --all-targets
cargo test --all-targets
cargo test --doc
cargo test --all-features --all-targets
cargo test --all-features --doc
```

## Run the Examples

From the `rust` directory:

```sh
cargo run --example dhtnode
cargo run --features async --example dhtnode_async
cargo run --features serde --example dhtnode_async
```

The callback example contacts a public bootstrap server. The async example uses
two loopback nodes; enabling `serde` also demonstrates typed MessagePack records.