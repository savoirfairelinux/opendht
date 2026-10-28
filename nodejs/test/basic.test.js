import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { EventEmitter, once } from 'node:events';
import { createServer } from 'node:http';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { Worker } from 'node:worker_threads';
import { DhtRunner, hash, version } from '../index.js';

const moduleURL = new URL('../index.js', import.meta.url).href;
const exampleURL = new URL('../examples/dhtnode.js', import.meta.url);
const example = fileURLToPath(exampleURL);

function startNode() {
    const runner = new DhtRunner();
    runner.run({ port: 0, ipv4: '127.0.0.1', ipv6: '::1' });
    return runner;
}

test('hashes strings and binary data without truncating NUL bytes', () => {
    assert.match(version, /^\d+\./);
    assert.equal(hash('hello'), 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d');
    assert.equal(hash('hello'), hash(Buffer.from('hello')));
    assert.notEqual(hash('hello\0world'), hash('hello'));
    assert.throws(() => hash(42), TypeError);
});

test('runner lifecycle and argument validation', async () => {
    const runner = new DhtRunner();
    assert.equal(runner.isRunning(), false);
    assert.throws(() => runner.get(hash('idle')), /running/i);
    assert.throws(() => runner.getAll(hash('idle')), /running/i);
    assert.throws(() => runner.run({ port: -1 }), RangeError);
    assert.throws(() => runner.run({ port: 65536 }), RangeError);
    assert.throws(() => runner.run({ port: 1.5 }), RangeError);
    runner.run({ port: 0, ipv4: '127.0.0.1', ipv6: '::1' });
    try {
        assert.equal(runner.isRunning(), true);
        assert.ok(runner.getBoundPort() > 0);
        assert.match(runner.getNodeId(), /^[0-9a-f]{40}$/);
        assert.throws(() => runner.run(), /already/i);
        assert.throws(() => runner.get('short'), /hash/i);
        assert.throws(() => runner.get('z'.repeat(40)), /hash/i);
        assert.throws(() => runner.put(hash('bad'), 'text'), TypeError);
        assert.throws(() => runner.put(hash('bad'), Buffer.alloc(0), { id: 1 }), TypeError);
        assert.throws(() => runner.put(hash('bad'), Buffer.alloc(0), { id: -1n }), RangeError);
        assert.throws(() => runner.put(hash('bad'), Buffer.alloc(0), { id: 1n << 64n }), RangeError);
        assert.throws(() => runner.put(hash('bad'), Buffer.alloc(0), { type: 65536 }), RangeError);
    } finally {
        const closing = runner.close();
        assert.equal(runner.close(), closing);
        await closing;
    }
    assert.equal(runner.isRunning(), false);
    assert.throws(() => runner.run(), /closed/i);
    assert.throws(() => runner.get(hash('closed')), /closed/i);
});

test('closing an idle runner is supported', async () => {
    const runner = new DhtRunner();
    await runner.close();
    await runner.close();
    assert.equal(runner.isRunning(), false);
});

test('runner reports per-family connectivity changes and snapshots', { timeout: 15000 }, async () => {
    const runner = new DhtRunner();
    const peer = startNode();
    const changes = [];
    runner.on('statusChanged', status => changes.push(status));
    try {
        assert.deepEqual(runner.getStatus(), { ipv4: 'disconnected', ipv6: 'disconnected' });
        runner.run({ port: 0, ipv4: '127.0.0.1', ipv6: '::1' });
        const connected = new Promise((resolve, reject) => {
            const signal = AbortSignal.timeout(10000);
            signal.addEventListener('abort', () => reject(signal.reason), { once: true });
            runner.on('statusChanged', status => {
                if (status.ipv4 === 'connected') resolve(status);
            });
        });
        runner.bootstrap('127.0.0.1', peer.getBoundPort());
        peer.bootstrap('127.0.0.1', runner.getBoundPort());
        const status = await connected;
        assert.equal(status.ipv4, 'connected');
        assert.ok(['disconnected', 'connecting', 'connected'].includes(status.ipv6));
        assert.deepEqual(runner.getStatus(), status);
        status.ipv4 = 'changed by consumer';
        assert.equal(runner.getStatus().ipv4, 'connected');
        await runner.close();
        const count = changes.length;
        await new Promise(resolve => setImmediate(resolve));
        assert.equal(changes.length, count);
        assert.deepEqual(runner.getStatus(), { ipv4: 'disconnected', ipv6: 'disconnected' });
    } finally {
        await Promise.all([runner.close(), peer.close()]);
    }
});

test('invalid bind addresses produce JS exceptions', async () => {
    const runner = new DhtRunner();
    try {
        assert.throws(() => runner.run({ ipv4: '192.0.2.1', ipv6: '2001:db8::1' }));
    } finally {
        await runner.close();
    }
});

test('two loopback nodes exchange binary values and cancel listeners', { timeout: 20000 }, async () => {
    const writer = startNode();
    const reader = startNode();
    const events = new EventEmitter();
    const key = hash('node-addon-api integration');
    const payload = Buffer.from([0, 1, 255, 0, 42]);
    let subscription;
    let retainedValue;
    try {
        writer.bootstrap('127.0.0.1', reader.getBoundPort());
        reader.bootstrap('127.0.0.1', writer.getBoundPort());
        subscription = reader.listen(key, (value, expired) => {
            if (!expired) events.emit('value', value);
        });
        const received = once(events, 'value', { signal: AbortSignal.timeout(10000) });
        assert.equal(await writer.put(key, payload, {
            id: 18446744073709551614n,
            type: 0,
            userType: 'nodejs-test',
            permanent: true,
        }), true);
        const [value] = await received;
        assert.equal(value.id, 18446744073709551614n);
        assert.equal(value.type, 0);
        assert.ok(Buffer.isBuffer(value.data));
        assert.deepEqual(value.data, payload);
        assert.equal(value.userType, 'nodejs-test');
        assert.equal(typeof value.seq, 'number');
        assert.equal(value.owner, null);
        assert.equal(value.isSigned, false);
        assert.equal(value.isEncrypted, false);
        value.data.fill(7);
        const values = await reader.getAll(key);
        retainedValue = values.find(candidate => candidate.id === value.id);
        assert.ok(retainedValue);
        assert.deepEqual(retainedValue.data, payload);
        subscription.cancel();
        subscription.cancel();
    } finally {
        subscription?.cancel();
        await Promise.all([writer.close(), reader.close()]);
    }
    assert.deepEqual(retainedValue.data, payload);
});

test('close settles pending operations and suppresses queued listener deliveries', { timeout: 10000 }, async () => {
    const runner = startNode();
    let deliveries = 0;
    const subscription = runner.listen(hash('closing'), () => deliveries++);
    const pending = runner.getAll(hash('unreachable'));
    const settled = assert.rejects(pending, { code: 'ERR_DHT_CLOSED' });
    await runner.close();
    await settled;
    subscription.cancel();
    assert.equal(deliveries, 0);
});

test('get iterators settle pending reads on cancellation and reject on runner close', { timeout: 10000 }, async () => {
    const runner = startNode();
    try {
        const cancelled = runner.get(hash('cancel get'));
        assert.equal(cancelled[Symbol.asyncIterator](), cancelled);
        const pending = [cancelled.next(), cancelled.next()];
        await cancelled.return();
        cancelled.cancel();
        assert.deepEqual(await Promise.all(pending), [
            { value: undefined, done: true },
            { value: undefined, done: true },
        ]);
        assert.deepEqual(await cancelled.next(), { value: undefined, done: true });

        const closing = runner.get(hash('close get'));
        const rejected = assert.rejects(closing.next(), { code: 'ERR_DHT_CLOSED' });
        await runner.close();
        await rejected;
        await assert.rejects(closing.next(), { code: 'ERR_DHT_CLOSED' });
    } finally {
        await runner.close();
    }
});

test('async listeners deliver queued values and cancel on loop exit', { timeout: 15000 }, async () => {
    const writer = startNode();
    const reader = startNode();
    const key = hash('async listener');
    let iterator;
    try {
        writer.bootstrap('127.0.0.1', reader.getBoundPort());
        reader.bootstrap('127.0.0.1', writer.getBoundPort());
        iterator = reader.listen(key);
        assert.equal(iterator[Symbol.asyncIterator](), iterator);
        const pending = iterator.next();
        assert.equal(await writer.put(key, Buffer.from('first'), { id: 1n }), true);
        const first = await pending;
        assert.equal(first.done, false);
        assert.equal(first.value.expired, false);
        assert.equal(first.value.value.id, 1n);
        assert.equal(first.value.value.data.toString(), 'first');

        assert.equal(await writer.put(key, Buffer.from('second'), { id: 2n }), true);
        for await (const { value, expired } of iterator) {
            assert.equal(expired, false);
            assert.equal(value.id, 2n);
            assert.equal(value.data.toString(), 'second');
            break;
        }
        assert.deepEqual(await iterator.next(), { value: undefined, done: true });
        iterator.cancel();
    } finally {
        iterator?.cancel();
        await Promise.all([writer.close(), reader.close()]);
    }
});

test('async listener cancellation settles concurrent reads and drops buffered values', { timeout: 10000 }, async () => {
    const runner = startNode();
    const peer = startNode();
    const key = hash('async cancellation');
    let iterator;
    try {
        runner.bootstrap('127.0.0.1', peer.getBoundPort());
        peer.bootstrap('127.0.0.1', runner.getBoundPort());
        iterator = runner.listen(key);
        const pending = [iterator.next(), iterator.next()];
        iterator.cancel();
        iterator.cancel();
        assert.deepEqual(await Promise.all(pending), [
            { value: undefined, done: true },
            { value: undefined, done: true },
        ]);
        assert.equal(await runner.put(key, Buffer.from('cancelled'), { id: 3n }), true);
        assert.deepEqual(await iterator.next(), { value: undefined, done: true });

        const buffered = runner.listen(key);
        await runner.getAll(key);
        await buffered.return();
        assert.deepEqual(await buffered.next(), { value: undefined, done: true });
    } finally {
        iterator?.cancel();
        await Promise.all([runner.close(), peer.close()]);
    }
});

test('async listener throw, disposal, and runner close settle pending reads', { timeout: 10000 }, async () => {
    const runner = startNode();
    try {
        const thrown = runner.listen(hash('async throw'));
        const pendingThrow = thrown.next();
        const failure = new Error('consumer failed');
        await assert.rejects(thrown.throw(failure), error => error === failure);
        assert.deepEqual(await pendingThrow, { value: undefined, done: true });
        assert.deepEqual(await thrown.next(), { value: undefined, done: true });

        const disposed = runner.listen(hash('async dispose'));
        const pendingDispose = disposed.next();
        await disposed[Symbol.asyncDispose]();
        assert.deepEqual(await pendingDispose, { value: undefined, done: true });

        const closing = runner.listen(hash('async close'));
        const pendingClose = [closing.next(), closing.next()];
        const close = runner.close();
        assert.equal(runner.close(), close);
        assert.deepEqual(await Promise.all(pendingClose), [
            { value: undefined, done: true },
            { value: undefined, done: true },
        ]);
        await close;
        assert.deepEqual(await closing.next(), { value: undefined, done: true });
        assert.throws(() => runner.listen(hash('closed iterator')), /closed/i);
    } finally {
        await runner.close();
    }
});

test('proxy configuration validates option types before starting', async () => {
    const runner = new DhtRunner();
    try {
        assert.throws(() => runner.run({ proxyServer: 42 }), TypeError);
        assert.throws(() => runner.run({ proxyUserAgent: false }), TypeError);
        assert.throws(() => runner.run({ proxyUserAgent: 'client\r\nInjected: header' }), TypeError);
        assert.throws(() => runner.run({ proxyServer: 'http://127.0.0.1\0' }), TypeError);
        assert.throws(() => runner.run({ proxyServer: 'ftp://127.0.0.1' }), /http/i);
        assert.throws(() => runner.run({ proxyServer: 'not a URL' }), /url/i);
        assert.equal(runner.isRunning(), false);
        runner.run({ port: 0, ipv4: '127.0.0.1', ipv6: '::1', proxyServer: '' });
        assert.ok(runner.getBoundPort() > 0);
    } finally {
        await runner.close();
    }
});

test('proxy configuration routes operations through HTTP with a custom user agent', { timeout: 15000 }, async () => {
    const runner = new DhtRunner();
    const requests = [];
    const values = new Map();
    let streamNextGet = false;
    let streamResponse;
    const server = createServer(async (request, response) => {
        response.setHeader('content-type', 'application/json');
        if (request.url === '/') {
            response.end(JSON.stringify({
                node_id: hash('proxy fixture'),
                ipv4: { good: 1 },
                ipv6: {},
                public_ip: '127.0.0.1',
            }));
            return;
        }
        requests.push({ method: request.method, url: request.url, userAgent: request.headers['user-agent'] });
        if (request.url === `/key/${hash('proxy failure')}`) {
            response.statusCode = 500;
            response.end();
            return;
        }
        if (request.method === 'POST') {
            const chunks = [];
            for await (const chunk of request) chunks.push(chunk);
            const value = JSON.parse(Buffer.concat(chunks).toString());
            values.set(request.url, value);
            response.end(JSON.stringify(value));
        } else {
            const value = values.get(request.url);
            const body = value ? `${JSON.stringify(value)}\n` : '';
            if (streamNextGet) {
                streamNextGet = false;
                streamResponse = response;
                response.write(body);
            } else response.end(body);
        }
    });
    server.listen(0, '127.0.0.1');
    try {
        await once(server, 'listening');
        runner.run({
            proxyServer: `http://127.0.0.1:${server.address().port}`,
            proxyUserAgent: 'opendht-node-test/1.0',
            persistPath: '',
        });
        const key = hash('proxy configuration');
        const payload = Buffer.from([0, 255, 42]);
        assert.equal(await runner.put(key, payload, { id: 42n }), true);
        const received = await runner.getAll(key);
        assert.equal(received.length, 1);
        assert.equal(received[0].id, 42n);
        assert.deepEqual(received[0].data, payload);

        streamNextGet = true;
        const iterator = runner.get(key);
        const first = await iterator.next();
        assert.equal(first.done, false);
        assert.equal(first.value.id, 42n);
        assert.deepEqual(first.value.data, payload);
        assert.equal(streamResponse.writableEnded, false);
        streamResponse.end();
        assert.deepEqual(await iterator.next(), { value: undefined, done: true });
        assert.deepEqual(await iterator.next(), { value: undefined, done: true });
        assert.deepEqual(requests.map(request => request.method), ['POST', 'GET', 'GET']);
        assert.ok(requests.every(request => request.url === `/key/${key}`));
        assert.ok(requests.every(request => request.userAgent === 'opendht-node-test/1.0'));

        const empty = runner.get(hash('proxy empty'));
        assert.deepEqual(await empty.next(), { value: undefined, done: true });
        const failed = runner.get(hash('proxy failure'));
        await assert.rejects(failed.next(), { code: 'ERR_DHT_GET_FAILED' });
        await assert.rejects(runner.getAll(hash('proxy failure')), { code: 'ERR_DHT_GET_FAILED' });

        const all = [];
        for await (const value of runner.get(key)) all.push(value);
        assert.equal(all.length, 1);
        assert.deepEqual(all[0].data, payload);

        streamNextGet = true;
        const cancelled = runner.get(key);
        for await (const value of cancelled) {
            assert.equal(value.id, 42n);
            break;
        }
        assert.equal(streamResponse.writableEnded, false);
        assert.deepEqual(await cancelled.next(), { value: undefined, done: true });
        streamResponse.end();
    } finally {
        streamResponse?.end();
        await runner.close();
        await new Promise((resolve, reject) => server.close(error => error ? reject(error) : resolve()));
    }
});

test('worker termination cleans up native runners', { timeout: 10000 }, async () => {
    const source = `
        import { parentPort } from 'node:worker_threads';
        import { DhtRunner, hash } from ${JSON.stringify(moduleURL)};
        const runner = new DhtRunner();
        runner.run({ port: 0, ipv4: '127.0.0.1', ipv6: '::1' });
        runner.listen(hash('worker'), () => {});
        parentPort.postMessage('ready');
    `;
    const worker = new Worker(new URL(`data:text/javascript,${encodeURIComponent(source)}`));
    try {
        await once(worker, 'message');
    } finally {
        await worker.terminate();
    }
});

test('listener callbacks may cancel themselves and close the runner', { timeout: 10000 }, async () => {
    const runner = startNode();
    const key = hash('reentrant listener');
    let deliveries = 0;
    let finish;
    const received = new Promise(resolve => { finish = resolve; });
    const subscription = runner.listen(key, () => {
        deliveries++;
        subscription.cancel();
        finish(runner.close());
    });
    const puts = [];
    for (let index = 0; index < 3000; index++) {
        puts.push(runner.put(key, Buffer.from('value'), { id: BigInt(index + 1) }).catch(error => {
            assert.equal(error.code, 'ERR_DHT_CLOSED');
        }));
    }
    try {
        await received;
        await Promise.all(puts);
        assert.equal(deliveries, 1);
    } finally {
        await runner.close();
    }
});

test('unref and garbage collection do not strand native threads', { timeout: 20000 }, async () => {
    for (const finish of ['runner.unref();', 'runner = null; setImmediate(() => global.gc());']) {
        await promisify(execFile)(process.execPath, ['--input-type=module', '--expose-gc', '-e', `
            import { DhtRunner } from ${JSON.stringify(moduleURL)};
            let runner = new DhtRunner();
            runner.run({ port: 0, ipv4: '127.0.0.1', ipv6: '::1' });
            ${finish}
        `], { timeout: 8000 });
    }
});

test('callback queue completes bursts beyond the former event limit', { timeout: 15000 }, async () => {
    const runner = startNode();
    const key = hash('unbounded callback queue');
    const errors = [];
    const count = 3000;
    runner.on('error', error => errors.push(error));
    const puts = [];
    try {
        for (let index = 0; index < count; index++)
            puts.push(runner.put(key, Buffer.from('value'), { id: BigInt(index + 1) }));
        const results = await Promise.all(puts);
        assert.equal(results.length, count);
        assert.ok(results.every(result => typeof result === 'boolean'));
        assert.equal(runner.isRunning(), true);
        assert.deepEqual(errors, []);
    } finally {
        await runner.close();
    }
});

test('dhtnode example prints help and validates its port', async () => {
    const { stdout } = await promisify(execFile)(process.execPath, [example, '--help']);
    assert.match(stdout, /Usage:.*dhtnode/);
    assert.match(stdout, /bootstrap/);
    await assert.rejects(promisify(execFile)(process.execPath, [example, '--port', '65536']), error => {
        assert.equal(error.code, 1);
        assert.match(error.stderr, /port/i);
        return true;
    });
});

test('dhtnode example accepts piped commands and shuts down on EOF', { timeout: 20000 }, async () => {
    const peer = startNode();
    try {
        const execution = promisify(execFile)(process.execPath, [example,
            '--port', '0', '--ipv4', '127.0.0.1',
            '--bootstrap', '127.0.0.1', '--bootstrap-port', String(peer.getBoundPort()),
        ], { timeout: 15000 });
        let output = '';
        let sentReads = false;
        execution.child.stdout.on('data', data => {
            output += data;
            if (!sentReads && /Stored example/.test(output) && /Stored signed/.test(output)) {
                sentReads = true;
                execution.child.stdin.end('get example\nget signed\ncancel example\n');
            }
        });
        execution.child.stdin.write('listen example\nput example hello world\nsign signed signed message\n');
        const { stdout, stderr } = await execution;
        assert.equal(stderr, '');
        assert.match(stdout, /Node [0-9a-f]{40}/);
        assert.match(stdout, /hello world/);
        assert.match(stdout, /signed message.*\[signed\]/);
        assert.match(stdout, /Cancelled example/);
        assert.match(stdout, /Connectivity: IPv4 connected, IPv6 (disconnected|connecting|connected)/);
    } finally {
        await peer.close();
    }
});

test('dhtnode example handles commands and quit while a get is pending', { timeout: 10000 }, async () => {
    const execution = promisify(execFile)(process.execPath, ['--input-type=module', '-e', `
        import { DhtRunner } from ${JSON.stringify(moduleURL)};
        const close = DhtRunner.prototype.close;
        let rejectGet;
        DhtRunner.prototype.getAll = function () {
            console.log('Get pending');
            return new Promise((resolve, reject) => { rejectGet = reject; });
        };
        DhtRunner.prototype.close = function () {
            rejectGet?.(new Error('DHT runner is closed'));
            return close.call(this);
        };
        await import(${JSON.stringify(exampleURL.href)});
    `, '--',
        '--port', '0', '--ipv4', '127.0.0.1', '--ipv6', '::1',
    ], { timeout: 8000 });
    let output = '';
    execution.child.stdout.on('data', data => {
        output += data;
        if (/get KEY \| put KEY TEXT/.test(output)) execution.child.stdin.end('quit\n');
    });
    execution.child.stdin.write('get waiting\nhelp\n');
    const { stdout, stderr } = await execution;
    assert.match(stdout, /Get pending/);
    assert.match(stdout, /get KEY \| put KEY TEXT/);
    assert.equal(stderr, '');
});

test('dhtnode example shuts down on SIGTERM', { timeout: 10000 }, async () => {
    if (process.platform === 'win32') return;
    const execution = promisify(execFile)(process.execPath, [example, '--port', '0', '--ipv4', '127.0.0.1'], { timeout: 8000 });
    let output = '';
    execution.child.stdout.on('data', data => {
        output += data;
        if (/Node [0-9a-f]{40}/.test(output)) execution.child.kill('SIGTERM');
    });
    const { stderr } = await execution;
    assert.equal(stderr, '');
});