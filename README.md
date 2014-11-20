DhtCpp
===
A lightweight C++11 Distributed Hash Table implementation

 * Light C++11 Kademlia DHT library
 * Simple API
 * Support for arbitrary value types with common types built-in: simple blob (user data) or bittorrent-style "service announcement"
 * "Identity" layer with data signature and encryption (using GnuTLS)
 * Value edition authentified by the identity layer or with custom per-value-type hooks
 * Fast bootstrap and announce time
 * Originally based on https://github.com/jech/dht by Juliusz Chroboczek

***work in progress***

Dependencies
-
- GnuTLS 3.1+, used to compute hashes and for the identity layer.

TODO
-
 * Event listening
 * Documention
 * ...

Examples
-
```c++
dht::DhtRunner node;

// Launch a new dht node using generated RSA keys,
// and listen on port 4222.
node.run(4222, dht::crypto::generateIdentity());

// put some data on the dht
std::vector<uint8_t> some_data(5, 10);
node.put("unique_key", some_data);

// get data from the dht
node.get("other_unique_key", [](const std::vector<std::shared_ptr<Value>>& values) {
    // Callback called when values are found
    for (const auto& value : values)
        std::cout << "Found value: " << value << std::endl;
    return true; // return false to stop the search
});

```
