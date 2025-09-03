# OpenDHT

OpenDHT is a lightweight Distributed Hash Table implementation providing an easy to use distributed in-memory data store.

## Key Features

* Lightweight and scalable, designed for large networks and small devices
* High resilience to network disruption
* Public key cryptography layer providing optional data signature and encryption
* IPv4 and IPv6 support
* Python 3 bindings
* REST API with optional HTTP client+server with push notification support

Every node in the network can read and write values to the store. Values are distributed over the network with redundancy.

## Install

Install on Linux, macOS and Windows with:
```sh
pip install opendht
```

## Quick Example

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
import opendht.aio as dht

async with dht.DhtRunner() as node:
    node.bootstrap("bootstrap.jami.net", "4222")

    # put data, waiting for completion
    await node.put(dht.InfoHash.get("unique_key"), dht.Value(b'tata data'))

    # get all values at key
    results = await node.getAll(dht.InfoHash.get("unique_key"))
    for value in results:
        print(value)
    
    # same operation, but stream values as they come from the network
    with node.get(dht.InfoHash.get("unique_key")) as results:
        async for value in results:
            print(value)

    # listen for changes of values at key
    with node.listen(dht.InfoHash.get("unique_key")) as values:
        async for value, expired in values:
            print(value)
            if value.data == b'tata data':
                break
```

## Documentation

For more information, examples and documentation, or to repport issues, visit: https://opendht.net

## License

Copyright (C) 2014-2025 Savoir-faire Linux Inc.

OpenDHT is free software; you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation; either version 3 of the License, or (at your option) any later version.
