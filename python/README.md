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

## Node State Persistence

Set the state file path before starting a node:

```python
import threading
import opendht as dht

config = dht.DhtConfig()
config.setPersistPath("dht-state.msgpack")
node = dht.DhtRunner()
node.run(config=config)
stopped = threading.Event()
node.shutdown(stopped.set)
stopped.wait()
node.join()
```

The node loads its saved DHT node ID, known peers, and stored values on startup,
and saves state during `shutdown()`. Wait for the shutdown callback before
calling `join()` or reusing the state path; `join()` alone does not save state.
Port hints are
stored in a sibling file named `<path>_port.txt`; saved ports are reused when
available. The parent directory must already exist and be writable. Use a
different state path for each node.

Persistence is disabled by default. `config.setPersistPath("")` disables it
explicitly. This state does not include private keys or certificates; persist
cryptographic identities separately as described below.

## Identity Persistence

Keys can be imported from PEM or DER bytes. Private keys export PKCS#8 PEM;
public keys export DER. Certificates export their complete PEM chain.

```python
import opendht as dht

identity = dht.Identity.generate("my-node")

private_key_pem = identity.key.serialize(password)
certificate_pem = bytes(identity.certificate)
public_key_der = bytes(identity.publickey)

restored = dht.Identity(
    dht.PrivateKey(private_key_pem, password),
    dht.Certificate(certificate_pem),
)
public_key = dht.PublicKey(public_key_der)
node = dht.DhtRunner()
node.run(id=restored)
```

Here `password` is an application-supplied string. Save the exported bytes using
your application's storage, protect private key files, and keep the password
separate from the key. `bytes(private_key)` and `private_key.serialize()` without
a password export **unencrypted** private keys. Empty or malformed key data,
incorrect passwords, and passwords containing NUL characters raise exceptions.
Exporting an uninitialized key raises `ValueError`.

## Value Metadata

The following properties are readable and writable on `Value`, including values
returned by `get()` and `listen()`:

| Property | Type | Meaning |
|----------|------|---------|
| `type` | unsigned 16-bit integer | Native value type identifier |
| `seq` | unsigned 16-bit integer | Sequence number for signed value updates |
| `priority` | unsigned integer | Push priority: `0` high, `1` normal |
| `pushType` | string | Push notification type, such as `audioCall` |

```python
value = dht.Value(b"some binary data")
value.type = 42
value.seq = 1
value.priority = 1
value.pushType = "audioCall"
```

Set metadata before publishing the value. Numeric values outside the native
integer range raise `OverflowError`.

## Observability

`getNodeInfo()` returns a read-only `NodeInfo` snapshot with node identifiers,
IPv4/IPv6 routing statistics, bound ports, pending-operation count, and local
and remote storage counters. `getNodesStats(socket.AF_INET)` and
`getNodesStats(socket.AF_INET6)` return `NodeStats` snapshots. Snapshots remain
valid after the runner stops. `getPublicAddress()` returns known public
`SockAddr` objects; pass an address family to restrict the results, or use
`getPublicAddressStr()` for strings. These lists may be empty before discovery.
`getNodeMessageStats(incoming=True)` selects incoming message counters.

```python
info = node.getNodeInfo()
print(info.node_id, info.bound4, info.ipv4.good_nodes, info.storage_size)
print(node.getPublicAddressStr())

node.setOnStatusChanged(lambda ipv4, ipv6: print(ipv4.name, ipv6.name))
node.setOnStatusChanged(None)
```

The status callback receives two `NodeStatus` values: `Disconnected`,
`Connecting`, or `Connected`. Registration replaces the previous callback and
persists across restarts; `None` disables it. Core callbacks run on the DHT
thread while native locks are held: do not call snapshot getters, blocking
operations, or `join()` from them. The asyncio wrapper schedules status
callbacks on its event-loop thread, where snapshot getters are safe to use.

## Queries And Filtered Listeners

`query()` retrieves metadata rather than complete value payloads. Each row is
a dictionary keyed by `ValueField`. Network projections support `Id`,
`ValueType`, `OwnerPk`, and `UserType`; values are integers, an `InfoHash` owner
fingerprint, or a UTF-8 string respectively. Explicit sequence-number
projections are not supported by the native wire format.

```python
selection = dht.Select().field(dht.ValueField.Id).field(dht.ValueField.UserType)
query = dht.Query()
query.buildFrom(selection, dht.Where().userType("record"))
rows = node.query(key, query=query)

query = dht.Query("SELECT id,user_type WHERE user_type=record")
node.query(key, query_cb=lambda row: print(row) or True,
           done_cb=lambda ok, nodes: print(ok), query=query)
```

Without an explicit query, all four supported metadata fields are selected.
Supplying `query_cb` makes the core call nonblocking; returning `False` stops
delivery. The blocking core API returns the collected rows, as `get()` does.
The asyncio API offers `query()` as a context-managed async iterator and
`await queryAll()` as a collector; these raise `RuntimeError` on failure.

```python
rows = await node.queryAll(key, query=query)
with node.query(key, query=query) as results:
    async for row in results:
        print(row[dht.ValueField.Id])
```

Both core and asyncio `listen()` accept optional `where` and `filter` arguments.
`Where` is sent to the DHT to narrow the subscription; the Python predicate
runs locally. Existing two-argument core listeners are unchanged.

```python
token = node.listen(key, lambda value, expired: True,
                    where=dht.Where().userType("record"),
                    filter=lambda value: len(value.data) < 1024)
node.cancelListen(token)
```

## Documentation

For more information, examples and documentation, or to repport issues, visit: https://opendht.net

## License

Copyright (c) 2014-2026 Savoir-faire Linux Inc.

OpenDHT is released under the MIT License. See [LICENSE](LICENSE) for details.
