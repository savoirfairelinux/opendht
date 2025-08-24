# OpenDHT

OpenDHT is a lightweight C++17 Distributed Hash Table implementation providing an easy to use distributed in-memory data store.

## Key Features

* Lightweight and scalable, designed for large networks and small devices
* High resilience to network disruption
* Public key cryptography layer providing optional data signature and encryption
* IPv4 and IPv6 support
* Clean and powerful C++17 map API with Python 3 bindings
* REST API with optional HTTP client+server with push notification support

Every node in the network can read and write values to the store. Values are distributed over the network with redundancy.

## Quick Example

```python
import opendht as dht

node = dht.DhtRunner()
node.run()

# Join the network through any running node,
# here using a known bootstrap node.
node.bootstrap("bootstrap.jami.net", "4222")

# blocking call (provide callback arguments to make the call non-blocking)
node.put(dht.InfoHash.get("unique_key"), dht.Value(b'some binary data'))

results = node.get(dht.InfoHash.get("unique_key"))
for r in results:
    print(r)
```

## Documentation

For more information, examples, and documentation, visit: https://opendht.net

## License

Copyright (C) 2014-2025 Savoir-faire Linux Inc.

OpenDHT is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.
