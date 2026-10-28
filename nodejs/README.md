# OpenDHT Node.js Bindings

Initial Node-API bindings using `node-addon-api` directly over the C++ library.
Node.js 22.9 or later is required; the addon targets Node-API version 8.

## Install

```sh
npm install opendht
```

## Build

Install the native dependencies described in [BUILD.md](../BUILD.md), plus Node.js,
a C++17 compiler, and CMake 3.21 or later. Ninja is optional. Proxy-client support
defaults to enabled and requires ASIO, llhttp, RESTinio, and expected-lite headers.

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

For an existing build, change cached options directly with CMake, for example
`cmake -S . -B build -DOPENDHT_PROXY_CLIENT=ON`, then rebuild. A custom build can
disable proxy support with `-DOPENDHT_PROXY_CLIENT=OFF`; requesting a proxy then
throws an explicit unsupported-build error.

The loader checks local builds, then compatible Node-API binaries under `prebuilds/`.
Set `OPENDHT_NODE_BINDING` to an absolute addon path to select an explicit build.
Packaged binaries include OpenDHT and non-system native dependencies, so archive
installation does not require a compiler or a system OpenDHT installation.

## Usage

```js
import { DhtRunner, hash } from 'opendht';

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
        for await (const value of reader.get(key)) {
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
- `run({port, ipv4, ipv6, network, persistPath, identity})` starts a threaded node. Port 0
  selects a free port. The defaults bind both IP families on all interfaces.
  `persistPath` is optional; use an empty string to disable persistence.
  `proxyServer` and `proxyUserAgent` configure proxy mode (see below).
- `getBoundPort(4 | 6)` defaults to IPv4; `getNodeId()` returns the node's hex ID.
- `getStatus()` returns the latest JS-dispatched `{ipv4, ipv6}` connectivity
  snapshot. Each family is `'disconnected'`, `'connecting'`, or `'connected'`.
  `runner.on('statusChanged', status => {})` receives changes on the JS thread.
  New and closing/closed runners report both families as disconnected. No status
  events are delivered after close begins; close does not emit a final event.
- `bootstrap(host, port)` queues bootstrap discovery. Returning does not mean the
  peer is connected; subsequent DHT operations report their own completion.
- `put(key, Uint8Array, {id, type, userType, permanent})` copies the input and
  resolves to the native success boolean. IDs are unsigned 64-bit `bigint` values.
- `get(key)` returns an async iterator of values as they arrive. The iterator
  ends when the lookup completes, or rejects with `ERR_DHT_GET_FAILED` on failure.
  `getAll(key)` returns a single promise resolving to the complete value array.
  Values contain `id`, `type`, `seq`, `userType`, copied `Buffer` data, `isSigned`,
  `isEncrypted`, and an `owner` long fingerprint (or null for unsigned values).
- `listen(key, (value, expired) => {})` returns a listener with idempotent
  `cancel()`. Queued deliveries are suppressed after cancellation. Callback
  return values are ignored; callbacks may cancel or close the runner.
- `listen(key)` without a callback returns an async iterator of `{value, expired}`
  events. It continues until cancelled or the runner closes.
- `close()` is idempotent and returns the same promise on repeated calls. It
  waits off the JS thread for graceful shutdown, then joins the native threads.
  After two seconds it forces the join if graceful shutdown has not completed.
  Pending operations reject with `ERR_DHT_CLOSED`. A closed runner cannot restart.
- `ref()` and `unref()` control whether the runner keeps Node's event loop alive.
  Running nodes are referenced by default. `Symbol.asyncDispose` calls `close()`.

Callbacks run only on their owning JS thread. There is no polling timer or worker
thread waiting on each get/put. Explicitly close runners; GC cleanup and Node
environment cleanup hooks are fallbacks, including forced worker termination.
Pending operations, active listeners, and registered status handlers keep their
runner alive until completion, cancellation, handler removal, or explicit close.
Graceful persistence cannot be guaranteed if the process is killed.

The binding does not cap the callback queue, accumulated `getAll()` results, or
iterator buffers. Slow iterator consumers can accumulate values without
backpressure. Queued callbacks retain their native values until delivery or cleanup.

## Async Iteration

`get()` and callback-free `listen()` start immediately and return iterators with
`next()`, `return()`, `throw()`, `cancel()`, and `Symbol.asyncDispose`.
Leaving a `for await` loop with `break` or an exception cancels the subscription.
Explicit cancellation discards buffered values and settles pending reads as done.
Closing the runner rejects active get iterators with `ERR_DHT_CLOSED`; listener
iterators end normally. Successful get completion preserves unread buffered values.

```js
for await (const value of runner.get(hash('example'))) {
  console.log(value.id, value.data);
}
const snapshots = await runner.getAll(hash('example'));

for await (const { value, expired } of runner.listen(hash('updates'))) {
  console.log(value.id, expired);
  if (expired) break;
}
```

## Proxy Configuration

Pass the URL of an OpenDHT HTTP(S) proxy at startup:

```js
runner.run({
  proxyServer: 'https://proxy.example.com',
  proxyUserAgent: 'my-app/1.0',
});
```

This selects the native OpenDHT proxy client, not an HTTP CONNECT or SOCKS proxy.
The node does not bind UDP sockets in this mode; `port`, `ipv4`, `ipv6`, and
`bootstrap()` are for direct DHT nodes. Omit `proxyServer` or use an empty string
for direct networking. Proxy settings are startup-only; create a new runner to
change transports or servers. Packaged binaries include proxy-client support.

## Crypto

`PrivateKey.generate(options)` and `Identity.generate(name, options)` return
promises and generate keys off the JS thread. Options accept `algorithm: 'ec'`
(the default, using OpenDHT's default EC curve) or `'rsa'`. RSA `bits` must be an
integer between 2048 and 8192; the default is 2048.

- `new PrivateKey(bytes, password?)` imports PEM/DER; `serialize(password?)`
  exports PKCS#8 PEM. A nonempty password encrypts the exported key.
- `privateKey.getPublicKey()` returns an owned public key. `sign(bytes)` and
  `decrypt(bytes)` return copied Buffers.
- `new PublicKey(bytes)` imports a public key; `serialize()` exports DER.
  `checkSignature(data, signature)` returns a boolean. `encrypt(bytes)` requires
  an RSA key; EC keys support signatures, not this encryption scheme.
- `new Certificate(bytes)` imports PEM/DER or a PEM certificate chain;
  `serialize()` exports a PEM chain. Import does not establish trust or validate
  the chain against a trust store. `getPublicKey()` returns its public key.
- Public keys and certificates expose `getId()` (40 hex characters) and
  `getLongId()` (64 hex characters).
- `new Identity(privateKey, certificate)` requires matching fingerprints.
  Its read-only `privateKey` and `certificate` properties return owned wrappers.
- Pass `identity` to `run()` to enable `putSigned(key, data, options?)` and
  `putEncrypted(key, data, recipientPublicKey, options?)`. Both return the same
  success boolean as `put()`. Encrypted values are signed by the sender and
  transparently decrypted for the recipient by OpenDHT's get/listen layer.

```js
import { Identity, DhtRunner } from 'opendht';

async function createAuthenticatedNode() {
    const identity = await Identity.generate('example', { algorithm: 'rsa', bits: 2048 });
    const runner = new DhtRunner();
    runner.run({ port: 0, identity });
    return { runner, identity };
}
```

Crypto methods take Uint8Array/Buffer inputs, not implicit text encodings. Imports
must be nonempty. Malformed handles/data,
mismatched identities, and unsupported encryption keys raise JS exceptions.
Only generation is asynchronous; import/export/sign/encrypt/decrypt are
synchronous and should be used from worker threads for large workloads.

## Packaging And CI

From a successful Release build:

```sh
npm run package
npm run test:package
```

`bundle` copies the addon into `prebuilds/<platform>-<arch>/`, gathers its runtime
dependencies, rewrites native loader paths, and copies dependency license
notices. macOS needs `dylibbundler` and Apple developer tools; Linux needs
`patchelf` and Debian/Ubuntu dependency copyright files. Windows uses the vcpkg
installed tree (`VCPKG_INSTALLED_DIR`, `VCPKG_DEFAULT_TRIPLET`) and MSVC tools.
`OPENDHT_LIBRARY_PATH` adds native library search directories when bundling.
An explicit addon path may be passed to `npm run bundle -- /absolute/addon.node`.
Bundling replaces only the current platform's generated prebuild directory.

`test:package` creates an npm archive, installs it in a temporary consumer with
install scripts disabled and no dev dependencies, forces prebuild-only loading,
and runs the full runtime suite. Pass an archive file or a directory containing
one archive to test it directly, for example `npm run test:package -- dist`.
Only runtime JS, declarations, the example's TypeScript source, documentation,
and prebuilds are included in the archive. `prepack` compiles the example, so
archive creation needs the development dependencies; archive installation does not.

The [Node.js package workflow](../.github/workflows/nodejs-package.yml) builds:

| Target | Build Baseline |
| --- | --- |
| Linux x64 | Ubuntu 24.04 / glibc 2.39 (Noble dependency image) |
| macOS ARM64 and x64 | macOS 15 |
| Windows x64 | Windows Server 2022 / MSVC |

CI combines platform prebuilds into one npm archive and verifies that archive on
Node 22, 24, and 26 on each platform, including Ubuntu 24.04 and 26.04. Branch
pushes, pull requests, and manual runs build and test without publishing.
musl/Alpine and other architectures are not currently built. Node-API stability
does not remove OS/libc or native dependency compatibility requirements. Review
the included dependency licenses and source-distribution obligations before
redistributing binaries.

Query filters, AbortSignal support, certificate trust-store validation, CA
issuance controls, and runtime proxy switching remain future work.