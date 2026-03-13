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
./build/test_testName
```

## dhtnode

The `dhtnode` CLI tool is a simple DHT node implementation using `DhtRunner`.

---

## Commit

After implementing a feature or fixing a bug, commit your changes in clean, atomic commits with descriptive messages with format:
`topic: short description`

If any test are added or modified, commit them separately before the fix (if any).

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

Optional components (`DhtProxyServer`, `DhtProxyClient`, `PeerDiscovery`) are compiled in only when the corresponding CMake options are enabled.

---
