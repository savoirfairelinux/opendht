'use strict';

const native = process.env.OPENDHT_NODE_BINDING
	? require(process.env.OPENDHT_NODE_BINDING)
	: require('node-gyp-build')(__dirname);
const { EventEmitter } = require('node:events');
const { PublicKey, PrivateKey, Certificate, Identity, handle } = require('./crypto')(native);

function eventReporter(owner, event) {
    return value => { owner.deref()?.emit(event, value); };
}

class DhtRunner extends EventEmitter {
	#native;
	#closing;
	#listeners = 0;
	#pending = 0;

	constructor() {
		super();
        const owner = new WeakRef(this);
        this.#native = new native.NativeRunner(eventReporter(owner, 'error'), eventReporter(owner, 'statusChanged'));
	}

	#updateOwner() {
        this.#native.setOwner(this.#listeners || this.#pending || this.listenerCount('error')
            || this.listenerCount('statusChanged') ? this : null);
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
		if (options?.identity !== undefined) options = { ...options, identity: handle(options.identity, Identity) };
		this.#native.run(options);
	}
	isRunning() { return this.#native.isRunning(); }
	getBoundPort(family = 4) { return this.#native.getBoundPort(family); }
	getNodeId() { return this.#native.getNodeId(); }
    getStatus() { return this.#native.getStatus(); }
	bootstrap(host, port) { this.#native.bootstrap(host, port); }
	get(key) { return this.#track(this.#native.get(key)); }
	put(key, data, options) { return this.#track(this.#native.put(key, data, options)); }
	putSigned(key, data, options) { return this.#track(this.#native.putSigned(key, data, options)); }
	putEncrypted(key, data, recipient, options) {
		return this.#track(this.#native.putEncrypted(key, data, options, handle(recipient, PublicKey)));
	}

	listen(key, callback) {
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

	close() { return this.#closing ??= this.#native.close(); }
	ref() { this.#native.ref(); return this; }
	unref() { this.#native.unref(); return this; }
	[Symbol.asyncDispose]() { return this.close(); }
}

module.exports = { DhtRunner, PublicKey, PrivateKey, Certificate, Identity, hash: native.hash, version: native.version };