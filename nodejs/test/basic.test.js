'use strict';

const assert = require('node:assert/strict');
const { execFile } = require('node:child_process');
const { once } = require('node:events');
const { EventEmitter } = require('node:events');
const { test } = require('node:test');
const { promisify } = require('node:util');
const { Worker } = require('node:worker_threads');
const { DhtRunner, hash, version } = require('..');

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
        assert.deepEqual(value.data, payload);
        assert.equal(value.userType, 'nodejs-test');
        assert.equal(typeof value.seq, 'number');
        const values = await reader.get(key);
        assert.ok(values.some(candidate => candidate.id === value.id && candidate.data.equals(payload)));
        subscription.cancel();
        subscription.cancel();
    } finally {
        subscription?.cancel();
        await Promise.all([writer.close(), reader.close()]);
    }
});

test('close settles pending operations and suppresses queued listener deliveries', { timeout: 10000 }, async () => {
    const runner = startNode();
    let deliveries = 0;
    const subscription = runner.listen(hash('closing'), () => deliveries++);
    const pending = runner.get(hash('unreachable'));
    const settled = assert.rejects(pending, { code: 'ERR_DHT_CLOSED' });
    await runner.close();
    await settled;
    subscription.cancel();
    assert.equal(deliveries, 0);
});

test('worker termination cleans up native runners', { timeout: 10000 }, async () => {
    const worker = new Worker(`
        const { parentPort } = require('node:worker_threads');
        const { DhtRunner, hash } = require(${JSON.stringify(require.resolve('..'))});
        const runner = new DhtRunner();
        runner.run({ port: 0, ipv4: '127.0.0.1', ipv6: '::1' });
        runner.listen(hash('worker'), () => {});
        parentPort.postMessage('ready');
    `, { eval: true });
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
    const put = runner.put(key, Buffer.from('value')).catch(error => {
        assert.equal(error.code, 'ERR_DHT_CLOSED');
    });
    try {
        await received;
        await put;
        assert.equal(deliveries, 1);
    } finally {
        await runner.close();
    }
});

test('unref and garbage collection do not strand native threads', { timeout: 20000 }, async () => {
    const modulePath = JSON.stringify(require.resolve('..'));
    for (const finish of ['runner.unref();', 'runner = null; setImmediate(() => global.gc());']) {
        await promisify(execFile)(process.execPath, ['--expose-gc', '-e', `
            const { DhtRunner } = require(${modulePath});
            let runner = new DhtRunner();
            runner.run({ port: 0, ipv4: '127.0.0.1', ipv6: '::1' });
            ${finish}
        `], { timeout: 8000 });
    }
});

test('queue overflow reports an error and rejects close', { timeout: 15000 }, async () => {
    const runner = startNode();
    const key = hash('bounded listener queue');
    const reported = once(runner, 'error');
    const subscription = runner.listen(key, () => { });
    const puts = [];
    try {
        for (let index = 0; index < 3000; index++) {
            puts.push(runner.put(key, Buffer.from('value'), { id: BigInt(index + 1) }).catch(error => {
                assert.equal(error.code, 'ERR_DHT_OVERFLOW');
            }));
        }
        const deadline = performance.now() + 5000;
        while (runner.isRunning() && performance.now() < deadline) { }
        assert.equal(runner.isRunning(), false);
        const [error] = await reported;
        assert.equal(error.code, 'ERR_DHT_OVERFLOW');
        await Promise.all(puts);
        await assert.rejects(runner.close(), { code: 'ERR_DHT_OVERFLOW' });
    } finally {
        subscription.cancel();
        await runner.close().catch(() => { });
    }
});

test('dhtnode example prints help and validates its port', async () => {
    const example = require('node:path').resolve(__dirname, '../examples/dhtnode.js');
    const { stdout } = await promisify(execFile)(process.execPath, [example, '--help']);
    assert.match(stdout, /Usage:.*dhtnode\.js/);
    assert.match(stdout, /bootstrap/);
    await assert.rejects(promisify(execFile)(process.execPath, [example, '--port', '65536']), error => {
        assert.equal(error.code, 1);
        assert.match(error.stderr, /port/i);
        return true;
    });
});

test('dhtnode example accepts piped commands and shuts down on EOF', { timeout: 20000 }, async () => {
    const peer = startNode();
    const example = require('node:path').resolve(__dirname, '../examples/dhtnode.js');
    try {
        const execution = promisify(execFile)(process.execPath, [example,
            '--port', '0', '--ipv4', '127.0.0.1',
            '--bootstrap', '127.0.0.1', '--bootstrap-port', String(peer.getBoundPort()),
        ], { timeout: 15000 });
        execution.child.stdin.end('listen example\nput example hello world\nsign signed signed message\nget example\nget signed\ncancel example\n');
        const { stdout, stderr } = await execution;
        assert.equal(stderr, '');
        assert.match(stdout, /Node [0-9a-f]{40}/);
        assert.match(stdout, /hello world/);
        assert.match(stdout, /signed message.*\[signed\]/);
        assert.match(stdout, /Cancelled example/);
    } finally {
        await peer.close();
    }
});

test('dhtnode example shuts down on SIGTERM', { timeout: 10000 }, async () => {
    if (process.platform === 'win32') return;
    const example = require('node:path').resolve(__dirname, '../examples/dhtnode.js');
    const execution = promisify(execFile)(process.execPath, [example, '--port', '0', '--ipv4', '127.0.0.1'], { timeout: 8000 });
    let output = '';
    execution.child.stdout.on('data', data => {
        output += data;
        if (/Node [0-9a-f]{40}/.test(output)) execution.child.kill('SIGTERM');
    });
    const { stderr } = await execution;
    assert.equal(stderr, '');
});