DhtCpp
===
A lightweight C++11 Distributed Hash Table implementation

 * Light C++11 DHT implementation
 * Simple API
 * Support for arbitrary value types with common types built-in: simple blob (user data) or bittorrent-style "service announcement"
 * "Identity" layer with data signature and encryption (using GnuTLS)
 * Value edition authentified by the identity layer or with custom per-value-type hooks
 * Fast bootstrap and announce time
 * Originally based on https://github.com/jech/dht

***work in progress***

Dependencies
-
- GnuTLS 3.1+, used to compute hashes and for the identity layer.

todo
-
 * Event listening
 * Documention
 * ...
