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

## Installation

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

## Documentation

For more information, examples and documentation, or to repport issues, visit: https://opendht.net

## License

Copyright (c) 2014-2026 Savoir-faire Linux Inc.

OpenDHT is released under the MIT License. See [LICENSE](LICENSE) for details.
