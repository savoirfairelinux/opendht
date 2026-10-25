# Rust bindings for opendht

## Build

Install rust on your system (https://rustup.rs/ is the recommanded way). Once done:

```
cargo build
```

### With Meson

From the repository root:

```sh
meson setup build-rust -Drust=enabled -Dc=enabled -Dpython=disabled
meson compile -C build-rust rust-bindings
meson test -C build-rust Rust --print-errorlogs
```

The Rust feature is disabled by default. Enabling it requires Cargo, the C
bindings, and shared native libraries (`-Ddefault_library=shared`, the default,
or `both`). Meson builds the Rust library and examples against the native
libraries in the same build directory; no OpenDHT installation is needed.
Cargo artifacts are stored under `build-rust/rust`. The Rust test target is
available when Meson's `tests` feature is enabled.

## Run tests

```
cargo test
```

## Run dht node

```
cargo run --example dhtnode
```