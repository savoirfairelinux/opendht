# OpenDHT Node.js Bindings

Initial Node-API bindings using `node-addon-api` directly over the C++ library.
The package is private while its API and binary distribution are being developed.
Node.js 22.9 or later is required; the addon targets Node-API version 8.

## Build

Install the native dependencies described in [BUILD.md](../BUILD.md), plus Node.js,
a C++17 compiler, and CMake 3.21 or later. Ninja is optional.

```sh
cd nodejs
npm ci
npm run build
npm test
npm run typecheck
```

CMake.js builds OpenDHT from the parent source directory in `nodejs/build/native`.
It does not change the repository's existing build directory. Tools, Python,
peer discovery, documentation, and native tests default to disabled in this build.
Native CMake options can be passed through, for example:

```sh
npm run build -- --CDOPENDHT_PEER_DISCOVERY=ON
```

The default loader uses `build/Release/opendht.node`. Set `OPENDHT_NODE_BINDING`
to an absolute addon path when using a different build directory or configuration.
The current build uses local native libraries and their build-tree runtime paths;
it is not yet a relocatable npm binary distribution. No prebuilt binaries are provided.

## Usage

```js
const { DhtRunner, hash } = require('./nodejs');

async function main() {
    const writer = new DhtRunner();
    const reader = new DhtRunner();
    try {
        writer.run({ port: 0, ipv4: '127.0.0.1', ipv6: '::1' });
        reader.run({ port: 0, ipv4: '127.0.0.1', ipv6: '::1' });
        writer.bootstrap('127.0.0.1', reader.getBoundPort());
        reader.bootstrap('127.0.0.1', writer.getBoundPort());
        const key = hash('example');
        const stored = await writer.put(key, Buffer.from('hello'), { id: 42n });
        if (!stored) throw new Error('DHT put failed');
        for (const value of await reader.get(key)) {
            console.log(value.id, value.data.toString());
        }
    } finally {
        await Promise.all([writer.close(), reader.close()]);
    }
}

main().catch(console.error);
```

## API

- `hash(string | Uint8Array)` returns a SHA-1 hash as a 40-character hex string.
  All get/put/listen keys must be hex hashes, not unhashed application keys.
- `version` is the underlying OpenDHT version.
- `run({port, ipv4, ipv6, network, persistPath})` starts a threaded node. Port 0
  selects a free port. The defaults bind both IP families on all interfaces.
  `persistPath` is optional; use an empty string to disable persistence.
- `getBoundPort(4 | 6)` defaults to IPv4; `getNodeId()` returns the node's hex ID.
- `bootstrap(host, port)` queues bootstrap discovery. Returning does not mean the
  peer is connected; subsequent DHT operations report their own completion.
- `put(key, Uint8Array, {id, type, userType, permanent})` copies the input and
  resolves to the native success boolean. IDs are unsigned 64-bit `bigint` values.
- `get(key)` resolves to value snapshots, or rejects with `ERR_DHT_GET_FAILED`.
  Values contain `id`, `type`, `seq`, `userType`, and copied `Buffer` data.
- `listen(key, (value, expired) => {})` returns a listener with idempotent
  `cancel()`. Queued deliveries are suppressed after cancellation. Callback
  return values are ignored; callbacks may cancel or close the runner.
- `close()` is idempotent and returns the same promise on repeated calls. It
  waits off the JS thread for graceful shutdown, then joins the native threads.
  After two seconds it forces the join if graceful shutdown has not completed.
  Pending operations reject with `ERR_DHT_CLOSED`. A closed runner cannot restart.
- `ref()` and `unref()` control whether the runner keeps Node's event loop alive.
  Running nodes are referenced by default. `Symbol.asyncDispose` calls `close()`.

Callbacks run only on their owning JS thread. There is no polling timer or worker
thread waiting on each get/put. Explicitly close runners; GC cleanup and Node
environment cleanup hooks are fallbacks, including forced worker termination.
Pending operations, active listeners, and registered error handlers keep their
runner alive until completion, cancellation, handler removal, or explicit close.
Graceful persistence cannot be guaranteed if the process is killed.

The cross-thread queue is limited to 1,024 events and 16 MiB, and each accumulated
get result is limited to 16 MiB and 65,536 values. Exceeding a limit closes the
runner, emits an `error` event with code `ERR_DHT_OVERFLOW`, and rejects pending
operations and `close()`. Install an `error` handler on long-lived runners. As
with other Node EventEmitters, an unhandled `error` event is fatal. There is no
silent dropping of events while continuing an apparently healthy listener.

## Current Scope

This first implementation covers lifecycle, persistence configuration, bootstrap,
plain values, get/put, and listeners. Identity/crypto wrappers, signed/encrypted
operations, query filters, async iterators, AbortSignal support, proxy controls,
and prebuilt package distribution remain future work. Node ABI stability does
not make OpenDHT or its native dependencies ABI-independent.