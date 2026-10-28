import { EventEmitter } from 'node:events';
import { constants } from 'node:os';
import { dlopen } from 'node:process';
import load from 'node-gyp-build';
import createCrypto from './crypto.js';

const binding = { exports: {} };
const flags = process.platform === 'linux'
    ? constants.dlopen.RTLD_LAZY | constants.dlopen.RTLD_DEEPBIND
    : undefined;
dlopen(binding, process.env.OPENDHT_NODE_BINDING || load.path(import.meta.dirname),
    flags);
const native = binding.exports;
const { PublicKey, PrivateKey, Certificate, Identity, handle } = createCrypto(native);

function eventReporter(owner, event) {
    return value => { owner.deref()?.emit(event, value); };
}

class DhtRunner extends EventEmitter {
    #native;
    #closing;
    #listeners = 0;
    #pending = 0;
    #iterators = new Set();

    constructor() {
        super();
        const owner = new WeakRef(this);
        this.#native = new native.NativeRunner(eventReporter(owner, 'statusChanged'));
    }

    #updateOwner() {
        this.#native.setOwner(this.#listeners || this.#pending || this.listenerCount('statusChanged') ? this : null);
    }

    #track(operation) {
        this.#pending++;
        this.#updateOwner();
        return operation.finally(() => {
            this.#pending--;
            this.#updateOwner();
        });
    }

    on(event, listener) { super.on(event, listener); this.#updateOwner(); return this; }
    addListener(event, listener) { return this.on(event, listener); }
    prependListener(event, listener) { super.prependListener(event, listener); this.#updateOwner(); return this; }
    removeListener(event, listener) { super.removeListener(event, listener); this.#updateOwner(); return this; }
    off(event, listener) { return this.removeListener(event, listener); }
    removeAllListeners(...args) { super.removeAllListeners(...args); this.#updateOwner(); return this; }

    run(options) {
        if (typeof options?.proxyServer === 'string' && options.proxyServer) {
            const proxy = new URL(options.proxyServer);
            if (proxy.protocol !== 'http:' && proxy.protocol !== 'https:')
                throw new TypeError('proxyServer must be an HTTP(S) URL');
        }
        if (options?.identity !== undefined) options = { ...options, identity: handle(options.identity, Identity) };
        this.#native.run(options);
    }
    isRunning() { return this.#native.isRunning(); }
    getBoundPort(family = 4) { return this.#native.getBoundPort(family); }
    getNodeId() { return this.#native.getNodeId(); }
    getStatus() { return this.#native.getStatus(); }
    bootstrap(host, port) { this.#native.bootstrap(host, port); }
    get(key) {
        return this.#iterate((push, finish) => {
            const operation = this.#native.get(key, push);
            this.#track(operation.done).then(() => finish(), finish);
            return () => this.#native.cancelGet(operation.token);
        }, true);
    }
    getAll(key) { return this.#track(this.#native.getAll(key)); }
    put(key, data, options) { return this.#track(this.#native.put(key, data, options)); }
    putSigned(key, data, options) { return this.#track(this.#native.putSigned(key, data, options)); }
    putEncrypted(key, data, recipient, options) {
        return this.#track(this.#native.putEncrypted(key, data, options, handle(recipient, PublicKey)));
    }

    listen(key, callback) {
        if (callback === undefined) {
            return this.#iterate(push => {
                const subscription = this.listen(key, (value, expired) => push({ value, expired }));
                return () => subscription.cancel();
            });
        }
        const token = this.#native.listen(key, callback);
        this.#listeners++;
        this.#updateOwner();
        let cancelled = false;
        return {
            cancel: () => {
                if (cancelled) return;
                this.#native.cancelListen(token);
                cancelled = true;
                this.#listeners--;
                this.#updateOwner();
            },
        };
    }

    #iterate(subscribe, rejectOnClose = false) {
        let values = [];
        let offset = 0;
        const pending = [];
        let done = false;
        let failure;
        const finish = error => {
            if (done) return;
            done = true;
            failure = error;
            unsubscribe();
            this.#iterators.delete(onClose);
            if (failure) {
                values = [];
                offset = 0;
            }
            for (const { resolve, reject } of pending.splice(0)) {
                if (failure) reject(failure);
                else resolve({ value: undefined, done: true });
            }
        };
        const cancel = () => {
            values = [];
            offset = 0;
            failure = undefined;
            finish();
        };
        const onClose = () => {
            if (rejectOnClose) {
                const error = new Error('DHT runner is closed');
                error.code = 'ERR_DHT_CLOSED';
                finish(error);
            } else cancel();
        };
        const unsubscribe = subscribe(value => {
            if (done) return;
            const waiter = pending.shift();
            if (waiter) waiter.resolve({ value, done: false });
            else values.push(value);
        }, finish);
        this.#iterators.add(onClose);
        return {
            next() {
                if (failure) return Promise.reject(failure);
                if (offset < values.length) {
                    const value = values[offset];
                    values[offset++] = undefined;
                    if (offset === values.length) {
                        values = [];
                        offset = 0;
                    }
                    return Promise.resolve({ value, done: false });
                }
                if (done) return Promise.resolve({ value: undefined, done: true });
                return new Promise((resolve, reject) => pending.push({ resolve, reject }));
            },
            return() {
                cancel();
                return Promise.resolve({ value: undefined, done: true });
            },
            throw(error) {
                cancel();
                return Promise.reject(error);
            },
            cancel,
            [Symbol.asyncIterator]() { return this; },
            [Symbol.asyncDispose]() { cancel(); return Promise.resolve(); },
        };
    }

    close() {
        if (!this.#closing) {
            this.#closing = this.#native.close();
            for (const cancel of this.#iterators) cancel();
        }
        return this.#closing;
    }
    ref() { this.#native.ref(); return this; }
    unref() { this.#native.unref(); return this; }
    [Symbol.asyncDispose]() { return this.close(); }
}

export { DhtRunner, PublicKey, PrivateKey, Certificate, Identity };
export const hash = native.hash;
export const version = native.version;