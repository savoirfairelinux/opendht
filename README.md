<img src="https://raw.githubusercontent.com/savoirfairelinux/opendht/master/resources/opendht_logo_512.png" width="100" align="right">
<br>
<h1 style="margin-top:10px">
    <a id="user-content-opendht-" class="anchor" href="/savoirfairelinux/opendht/blob/master/README.md#opendht-" aria-hidden="true"></a>OpenDHT
</h1>

![PyPI - Version](https://img.shields.io/pypi/v/opendht?style=flat)

A lightweight C++17 Distributed Hash Table implementation.

OpenDHT provides an easy to use distributed in-memory data store.
Every node in the network can read and write values to the store.
Values are distributed over the network, with redundancy.

 * Lightweight and scalable, designed for large networks and small devices
 * High resilience to network disruption
 * Public key cryptography layer providing optional data signature and encryption (using GnuTLS)
 * IPv4 and IPv6 support
 * Clean and powerful **C++17** map API
 * Bindings for **C, Rust & Python 3**
 * REST API with optional HTTP client+server with push notification support

## Documentation
See the wiki: <https://github.com/savoirfairelinux/opendht/wiki>

#### How to run a node

You can help contribute to the public network by running a stable node with a public IP address.
https://github.com/savoirfairelinux/opendht/wiki/Running-a-node-with-dhtnode

#### How-to build and install

Build instructions: see [BUILD.md](BUILD.md)

## Examples
### C++ example
The `tools` directory includes simple example programs :
* `dhtnode`, a command line tool, allowing to run a DHT node and perform operations supported by the library (get, put etc.) with text values.
* `dhtchat`, a very simple IM client working over the dht.

Example program launching a DHT node, connecting to the network and performing some basic operations:
```c++
#include <opendht.h>
#include <vector>

int main()
{
    dht::DhtRunner node;

    // Launch a dht node on a new thread, using a
    // generated RSA key pair, and listen on port 4222.
    node.run(4222, dht::crypto::generateIdentity(), true);

    // Join the network through any running node,
    // here using a known bootstrap node.
    node.bootstrap("bootstrap.jami.net", "4222");

    // put some data on the dht
    std::vector<uint8_t> some_data(5, 10);
    node.put("unique_key", some_data);

    // put some data on the dht, signed with our generated private key
    node.putSigned("unique_key_42", some_data);

    // get data from the dht
    node.get("other_unique_key", [](const std::vector<std::shared_ptr<dht::Value>>& values) {
        // Callback called when values are found
        for (const auto& value : values)
            std::cout << "Found value: " << *value << std::endl;
        return true; // return false to stop the search
    });

    // wait for dht threads to end
    node.join();
    return 0;
}
```

### Python 3 example

Install on Linux, macOS and Windows with:
```sh
pip install opendht
```

Using the simple, blocking API:
```python
import opendht as dht

node = dht.DhtRunner()
node.run()

# Join the DHT network through any running node,
# here using a known bootstrap node.
node.bootstrap("bootstrap.jami.net", "4222")

# blocking call (provide callback arguments to make the call non-blocking)
node.put(dht.InfoHash.get("unique_key"), dht.Value(b'some binary data'))

results = node.get(dht.InfoHash.get("unique_key"))
for value in results:
    print(value)
```

Or using asyncio:
```python
import asyncio
import opendht.aio as dht

async def dht_async_demo(key_str: str):
    # Start a new node using an async context manager.
    # It is also possible to call run()/await shutdown() manually.
    async with dht.DhtRunner(
        bootstrap=(("bootstrap.jami.net", "4222"),)
    ) as node:
        # compute key hash
        key = dht.InfoHash.get(key_str)

        # put data, waiting for completion
        await node.put(key, dht.Value(b'tata data'))

        # get all values at key
        results = await node.getAll(key)
        for value in results:
            print(value)
        
        # same operation, but stream values as they come from the network
        with node.get(key) as results:
            async for value in results:
                print(value)

        # listen for change of values at key
        with node.listen(key) as values:
            async for value, expired in values:
                print(value)
                if value.data == b'tata data':
                    break

asyncio.run(dht_async_demo("unique_key"))
```

## Dependencies
- msgpack-c 1.2+, used for data serialization.
- GnuTLS 3.3+, used for cryptographic operations.
- Nettle 2.4+, a GnuTLS dependency for crypto.
- {fmt} 9.0+, for log formatting.
- (optional) restinio used for the REST API.
- (optional) llhttp used for the REST API.
- (optional) jsoncpp 1.7.4-3+, used for the REST API.
- Build tested with GCC 9+ (GNU/Linux, Windows with MinGW), Clang/LLVM (GNU/Linux, Android, macOS, iOS).
- Build tested with Microsoft Visual Studio 2019, 2022

## Contact

IRC: join us on Libera.chat at [`#opendht`](https://web.libera.chat/#opendht).

## License
Copyright (C) 2014-2025 Savoir-faire Linux Inc.

OpenDHT is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

See COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html for the full GPLv3 license.

## Acknowledgements
This project was originally based on https://github.com/jech/dht by Juliusz Chroboczek.
