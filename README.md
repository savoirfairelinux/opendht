OpenDHT
===
A lightweight C++11 Distributed Hash Table implementation originally based on https://github.com/jech/dht by Juliusz Chroboczek.

 * Light and fast C++11 Kademlia DHT library.
 * Distributed shared key->value data-store
 * Clean and powerful distributed map API with storage of arbitrary binary values of up to 56 KB.
 * Optional public key cryptography layer providing data signature and encryption (using GnuTLS).
 * IPv4 and IPv6 support.
 * Python binding.

Documentation
-
See the wiki: <https://github.com/savoirfairelinux/opendht/wiki>

#### How-to build and install

Build instructions : <https://github.com/savoirfairelinux/opendht/wiki/Build-the-library>

#### How-to build a simple client app
```bash
g++ main.cpp -std=c++11 -lopendht -lgnutls
```

Examples
-
### C++ example
The `tools` directory includes simple example programs :
* `dhtnode`, a command line tool, mostly used for debuging, allowing to perform operations supported by the library (get, put etc.) with text values.
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
    node.bootstrap("bootstrap.ring.cx", "4222");

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
```python
import opendht as dht

node = dht.DhtRunner()
node.run()

# Join the network through any running node,
# here using a known bootstrap node.
node.bootstrap("bootstrap.ring.cx", "4222")

# blocking call (provide callback arguments to make the call non-blocking)
node.put(dht.InfoHash.get("unique_key"), dht.Value(b'some binary data'))

results = node.get(dht.InfoHash.get("unique_key"))
for r in results:
    print(r)
```

Dependencies
-
- msgpack-c 1.2+, used for data serialization.
- GnuTLS 3.1+, used for cryptographic operations.
- Nettle 2.4+, a GnuTLS dependency for crypto.
- Build tested with GCC 4.8+ (GNU/Linux, Android, Windows with MinGW), Clang/LLVM (Linux, OS X).
- Build tested with Microsoft Visual Studio 2015

Licence
-
Copyright (C) 2014-2016 Savoir-faire Linux Inc.

OpenDHT is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

See COPYING or https://www.gnu.org/licenses/gpl-3.0.en.html for the full GPLv3 licence.

This project is independent from another project called OpenDHT (Sean Rhea. Ph.D. Thesis, 2005), now extinct.

Donations
-
We gratefully accept Bitcoin donations to support OpenDHT development at: `bitcoin:3EykSd1An888efq4Bq3KaV3hJ3JQ4FPnwm`.
