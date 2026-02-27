# OpenDHT – Agent Instructions

## Build

### Primary: CMake (C++17)
```sh
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Debug -DBUILD_TESTING=ON -GNinja
ninja
```

### Common CMake options
| Option | Default | Purpose |
|--------|---------|---------|
| `OPENDHT_TOOLS` | ON | CLI tools (dhtnode, dhtchat, …) |
| `OPENDHT_C` | OFF | C language bindings |
| `OPENDHT_PYTHON` | OFF | Python 3 Cython bindings |
| `OPENDHT_PROXY_SERVER` | OFF | REST API proxy server (requires RESTinio + llhttp) |
| `OPENDHT_PROXY_CLIENT` | OFF | REST API proxy client |
| `OPENDHT_PEER_DISCOVERY` | OFF | Multicast local peer discovery |
| `OPENDHT_PUSH_NOTIFICATIONS` | OFF | Push notification support |
| `OPENDHT_SANITIZE` | OFF | AddressSanitizer + stack protector |

### Alternative: Meson (C++20)
```sh
meson setup build . && cd build && ninja
```

### Run tests
```sh
# Full suite
ctest --output-on-failure --test-dir build

# Single test executable
./build/test_dhtrunner
./build/test_crypto
./build/test_value
./build/test_infohash
./build/test_storage
./build/test_threadpool
```
Network-dependent tests (`test_http`, `test_dhtproxy`, `test_peerdiscovery`) require their corresponding CMake features enabled at configure time.

---

## Architecture

OpenDHT is a Kademlia-based DHT library. The implementation is layered:

```
DhtRunner          (public API — thread-safe, manages lifecycle & I/O threads)
  └── SecureDht    (GnuTLS crypto: signing, encryption, identity)
        └── Dht    (core DHT logic: routing, storage, find/get/put operations)
              └── NetworkEngine   (raw UDP sockets, message parsing, IPv4/IPv6)
```

- **`DhtRunner`** (`include/opendht/dhtrunner.h`, `src/dhtrunner.cpp`) — entry point for all users of the library. Wraps everything in a thread-pool and exposes async callbacks as well as blocking calls.
- **`Dht`** (`include/opendht/dht.h`, `src/dht.cpp`) — Kademlia protocol: routing table, k-buckets, value replication, expiry.
- **`SecureDht`** (`include/opendht/securedht.h`, `src/securedht.cpp`) — transparent encryption/signing layer on top of `Dht`. Identity is a GnuTLS certificate.
- **`NetworkEngine`** (`include/opendht/network_engine.h`, `src/network_engine.cpp`) — UDP socket layer, serializes/deserializes msgpack messages.
- **`RoutingTable`** (`include/opendht/routing_table.h`, `src/routing_table.cpp`) — Kademlia routing table with bucket splitting.
- **`Value`** (`include/opendht/value.h`) — the storable unit: binary blob, optional signature, optional encryption; typed via `ValueType`.
- **`InfoHash`** (`include/opendht/infohash.h`) — 20-byte SHA-1 identifier; alias `Hash<HASH_LEN>`.
- **Internal-only headers** (`src/storage.h`, `src/search.h`, `src/listener.h`, `src/request.h`, `src/parsed_message.h`) are not part of the public API.

Optional components (`DhtProxyServer`, `DhtProxyClient`, `PeerDiscovery`) are compiled in only when the corresponding CMake options are enabled.

---

## Key conventions

### Namespaces
All library code lives in `namespace dht`. Sub-namespaces: `dht::net`, `dht::crypto`, `dht::indexation`.

### Naming
- Types/classes: `PascalCase` — `DhtRunner`, `NetworkEngine`, `InfoHash`
- Methods/functions: `camelCase` — `getNodeId()`, `putEncrypted()`
- Constants: `UPPER_SNAKE_CASE` — `HASH_LEN`, `STORAGE_LIMIT_DEFAULT`, `STORAGE_LIMIT_UNLIMITED`
- Private member variables: `snake_case_` (trailing underscore)

### Smart pointers
`Sp<T>` is a project-wide alias for `std::shared_ptr<T>` (defined in `def.h`). Prefer it over spelling out `std::shared_ptr`.

### Code style (`.clang-format` enforced)
- Indent: 4 spaces, no tabs
- Column limit: 120
- Pointer alignment: left (`T* ptr`)
- Braces wrap after `class`, `struct`, function definitions; not after control statements
- Binary operators break before (not after)
- Constructor initializers: `BeforeComma` style

Run `clang-format -i <file>` before committing. CI also runs `clang-tidy` (config in `.clang-tidy`).

### Tests
Tests use **CppUnit**. Each feature has a `test_<name>.h` / `test_<name>.cpp` pair in `tests/`. Test classes inherit from `CppUnit::TestFixture` and use `CPPUNIT_TEST_SUITE()` macros. All test executables share `tests/tests_runner.cpp` as the entry point.

### Language bindings
- **C bindings**: `c/opendht.cpp` implements the C API declared in `c/opendht_c.h`.
- **Python bindings**: Cython (`.pyx`) in `python/opendht/`. An `asyncio`-compatible layer is in `python/opendht/aio.py`.
- **Rust bindings**: `rust/` is a separate Cargo workspace; it wraps the C bindings.

### Copyright header
Every source file should begin with:
```cpp
// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
```
