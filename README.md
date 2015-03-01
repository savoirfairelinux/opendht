OpenDHT
===
A lightweight C++11 Distributed Hash Table implementation

 * Light C++11 Kademlia DHT library
 * Simple API
 * Support for arbitrary value types (with common types built-in)
 * Optional crypto/identity layer with data signature and encryption (using GnuTLS)
 * Value edition authentified by the crypto layer or with custom per-value-type hooks
 * Fast bootstrap and announce time
 * Not compatible with Bittorrent DHT (mainline).
 * Originally based on https://github.com/jech/dht by Juliusz Chroboczek

***work in progress***

Example
-
```c++
#include <opendht.h>

int main() {
    dht::DhtRunner node;

    // Launch a dht node on a new thread, using a
    // generated RSA key pair, and listen on port 4222.
    node.run(4222, dht::crypto::generateIdentity(), true);

    // put some data on the dht
    std::vector<uint8_t> some_data(5, 10);
    node.put("unique_key", some_data);

    // put some data on the dht, signed with our generated private key
    node.putSigned("unique_key_42", some_data);

    // get data from the dht
    node.get("other_unique_key", [](const std::vector<std::shared_ptr<dht::Value>>& values) {
        // Callback called when values are found
        for (const auto& value : values)
            std::cout << "Found value: " << value << std::endl;
        return true; // return false to stop the search
    });
    
    // here we could wait for some operations to complete
    // instead of ending now.

    // wait for dht threads to end
    node.join();
}
```

How-to build and install
-
```bash
# clone the repo
git clone https://github.com/savoirfairelinux/opendht.git

# build and install
cd opendht
./autogen.sh && ./configure
make
sudo make install
```

How-to build a simple client app
-
```bash
g++ main.cpp -std=c++11 -lopendht -lgnutls
```

Licence
-
Copyright (C) 2014-2015 Savoir-Faire Linux Inc.

Licenced under the GNU General Public License version 3, though the core routing library (dht.cpp) is licenced under the MIT licence.

Dependencies
-
- GnuTLS 3.1+, used to compute hashes and for the identity layer.
- Build tested with GCC 4.8+ (Linux, Android, Windows with MinGW), Clang/LLVM (Linux, OS X).

TODO
-
 * Long term value persistance
 * Documentation
 * ...
