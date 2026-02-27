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
brew install gnutls msgpack-cxx argon2 asio readline jsoncpp fmt
```

## Build

Using CMake:

```sh
# Clone the repository
git clone https://github.com/savoirfairelinux/opendht.git

# Build and install
cd opendht
mkdir build && cd build
cmake -DCMAKE_INSTALL_PREFIX=/usr ..
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
      -DOPENDHT_PUSH_NOTIFICATIONS=ON \
      -DCMAKE_INSTALL_PREFIX=/usr ..
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

## Windows/MSVC

Building on Windows with MSVC is supported with VCPKG and CMake.

### Build with VCPKG in manifest mode

1. Install [VCPKG](https://github.com/microsoft/vcpkg) and required dependencies:
```ps1
git clone https://github.com/microsoft/vcpkg.git
cd vcpkg; .\bootstrap-vcpkg.bat
```

2. Use CMake preset for vcpkg:
```ps1
cd opendht
cmake --preset=vcpkg_manifest .
cmake --build .
```
