# Build the library

The build is currently tested on GNU/Linux, macOS, and Windows.

## Unix-like systems (Linux, macOS, MSYS2/MinGW, etc.)

## Install dependencies

### Debian 13

```sh
# Install dependencies
sudo apt install pkg-config libncurses5-dev libreadline-dev nettle-dev libgnutls28-dev libargon2-dev libmsgpack-dev libssl-dev libfmt-dev libjsoncpp-dev libhttp-parser-dev libasio-dev libmsgpack-cxx-dev

# Install Python binding dependencies
sudo apt-get install cython3 python3-dev python3-setuptools python3-build
```

Optionally, install RESTinio to enable the OpenDHT proxy client and server:
```sh
mkdir /usr/include/nonstd
wget https://raw.githubusercontent.com/martinmoene/expected-lite/master/include/nonstd/expected.hpp -O /usr/include/nonstd/expected.hpp

wget https://github.com/Stiffstream/restinio/releases/download/v.0.7.9/restinio-0.7.9.tar.bz2
tar -xjf restinio-0.7.9.tar.bz2
cd restinio-0.7.9/dev
cmake -DCMAKE_INSTALL_PREFIX=/usr -DRESTINIO_TEST=Off -DRESTINIO_SAMPLE=Off -DRESTINIO_BENCHMARK=Off -DRESTINIO_WITH_SOBJECTIZER=Off -DRESTINIO_DEP_STANDALONE_ASIO=system -DRESTINIO_DEP_LLHTTP=system -DRESTINIO_DEP_FMT=system -DRESTINIO_DEP_EXPECTED_LITE=system .
make && make install
```

To run openDHT on a different computer from the build computer, the following runtime dependencies are required:
```sh
sudo apt install libargon2-1 libjsoncpp26
```

### Ubuntu 24.04 and Debian 12

```sh
# Install dependencies
sudo apt install pkg-config libncurses5-dev libreadline-dev nettle-dev libgnutls28-dev libargon2-0-dev libmsgpack-dev libssl-dev libfmt-dev libjsoncpp-dev libhttp-parser-dev libasio-dev

# Install Python binding dependencies
sudo apt-get install cython3 python3-dev python3-setuptools python3-build
```

Optionally, install RESTinio to enable the OpenDHT proxy client and server:
```sh
mkdir /usr/include/nonstd
wget https://raw.githubusercontent.com/martinmoene/expected-lite/master/include/nonstd/expected.hpp -O /usr/include/nonstd/expected.hpp

wget https://github.com/Stiffstream/restinio/releases/download/v.0.7.9/restinio-0.7.9.tar.bz2
tar -xjf restinio-0.7.9.tar.bz2
cd restinio-0.7.9/dev
cmake -DCMAKE_INSTALL_PREFIX=/usr -DRESTINIO_TEST=Off -DRESTINIO_SAMPLE=Off -DRESTINIO_BENCHMARK=Off -DRESTINIO_WITH_SOBJECTIZER=Off -DRESTINIO_DEP_STANDALONE_ASIO=system -DRESTINIO_DEP_LLHTTP=system -DRESTINIO_DEP_FMT=system -DRESTINIO_DEP_EXPECTED_LITE=system .
make && make install
```

### Fedora

```sh
# Install GnuTLS, Readline and msgpack-c
sudo dnf install readline-devel gnutls-devel msgpack-devel asio-devel libargon2-devel fmt-devel
# Install python binding dependencies
sudo dnf install python3-Cython python3-devel redhat-rpm-config
```

### macOS

```sh
brew install gnutls msgpack-cxx argon2 asio readline jsoncpp fmt llhttp
```

## Build

Using CMake:

```sh
# Clone the repository
git clone https://github.com/savoirfairelinux/opendht.git

# Build and install
cd opendht
mkdir build && cd build
cmake ..
make -j$(nproc)
sudo make install
```

#### Example Configurations

Minimal build (libraries only):
```sh
cmake -DOPENDHT_TOOLS=OFF ..
```

Full-featured build with proxy support, Python, and C bindings:
```sh
cmake -DOPENDHT_PYTHON=ON \
      -DOPENDHT_C=ON \
      -DOPENDHT_PROXY_SERVER=ON \
      -DOPENDHT_PROXY_SERVER_IDENTITY=ON \
      -DOPENDHT_PROXY_CLIENT=ON \
      -DOPENDHT_PUSH_NOTIFICATIONS=ON ..
```

#### Common CMake options
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

## Node.js Bindings

Node-API bindings wrap the C++ API directly with `node-addon-api`, including
RSA/EC keys, certificates, identities, and signed/encrypted DHT operations.
With the native dependencies above, Node.js 22.9+, and CMake installed, run
`npm ci`, `npm run build`, `npm test`, and `npm run typecheck` from `nodejs/`.
This creates a separate native build without changing the existing build tree.
See [the Node.js binding guide](nodejs/README.md) for the API and current limits.
`npm run package` creates a platform prebuild with bundled native dependencies;
`npm run test:package` verifies installation outside the source tree. The Node.js
package CI builds Linux x64, macOS ARM64/x64, and Windows x64 prebuilds and checks
the assembled npm archive on Node 22, 24, and 26 before release attachment.

## C and Rust Bindings

Enable `OPENDHT_C=ON` to build the C ABI. With `BUILD_TESTING=ON`, CTest runs
`test_c`; Meson registers the same test as `CBindings` when `c` and `tests` are
enabled. Rust regression and callback-lifetime tests run with Cargo; see
[the Rust binding guide](rust/README.md) for build and library-path settings.

`dht_infohash` and `dht_pkid` have `uint32_t` alignment, matching the native hash
types, while retaining their 20-byte and 32-byte sizes. Rebuild consumers against
the updated header; foreign-language declarations must match this alignment.

C handles returned by constructors, imports, and reference functions are owned
and require their matching delete/unref function. Data views, string getters,
query fields, and callback arguments are borrowed: copy them or take a reference
before returning from the callback. `dht_sockaddr_array_delete` releases both the
public-address array and its elements.

Operation completion callbacks run once, including failure when pending work is
discarded on runner teardown. Listener release callbacks run after the native
registration is destroyed; deleting an operation token alone does not cancel its
listener. Cancel first, then delete the consumed token. Startup-context release
callbacks run after all native status/store callback captures are released, also
on startup failure. Certificate-store callbacks must invoke the supplied emitter
synchronously with borrowed certificates. Query-result views are callback-scoped.

`dht_runner_loop` drives non-threaded nodes. `dht_runner_join` waits for callbacks
and allows restart; never call it from a DHT callback. For persisted shutdown,
wait for the shutdown callback before joining. Push tokens can be polled without
blocking and must be deleted separately. `dht_push_token_poll` returns `EAGAIN`
while pending, 0 with the native outcome when ready, and an error code otherwise;
consume a successful result only once. Native push outcomes are 0 through 3 for
refresh/value events, 128 through 131 for ignored events, and 132 for errors.

## Windows/MSVC

Building on Windows with MSVC is supported with VCPKG and CMake.

### Build with VCPKG in manifest mode

1. Install [VCPKG](https://github.com/microsoft/vcpkg) 2026.10.16 and required dependencies:
```ps1
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg
git checkout 9eec002df1cd109f8f104cd966a763daf9751489
.\bootstrap-vcpkg.bat
```

2. Use CMake preset for vcpkg:
```ps1
cd opendht
cmake --preset=vcpkg_manifest .
cmake --build .
```

### CI

Windows CI uses [lukka/run-vcpkg](https://github.com/lukka/run-vcpkg) to acquire
and bootstrap the revision pinned by `default-registry.baseline` in
`vcpkg-configuration.json`. CMake uses the action's `VCPKG_ROOT` and installs
manifest dependencies on every run. Dependency-preparation jobs warm the binary
cache before the Windows build matrix starts.

Only ABI-keyed binary package archives are cached, not installed trees. The
supported [files provider](https://learn.microsoft.com/en-us/vcpkg/reference/binarycaching#files-provider)
is persisted with `actions/cache`; it does not use the removed `x-gha` provider
or require package-feed credentials. Cache keys include the target triplet,
manifests, overlay ports, run ID, and attempt, with restore prefixes for reuse.
Each run can save newly built archives without overwriting an immutable cache;
vcpkg validates package ABIs before reuse.
