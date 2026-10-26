'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { Certificate, DhtRunner, Identity, PrivateKey, PublicKey, hash } = require('..');

const payload = Buffer.from([0, 255, 1, 0, 42]);

test('RSA keys sign, encrypt, and survive password-protected serialization', async () => {
    const key = await PrivateKey.generate({ algorithm: 'rsa', bits: 2048 });
    const publicKey = key.getPublicKey();
    assert.match(publicKey.getId(), /^[0-9a-f]{40}$/);
    assert.match(publicKey.getLongId(), /^[0-9a-f]{64}$/);
    const signature = key.sign(payload);
    assert.equal(publicKey.checkSignature(payload, signature), true);
    assert.equal(publicKey.checkSignature(Buffer.from('other'), signature), false);
    assert.deepEqual(key.decrypt(publicKey.encrypt(payload)), payload);
    const restored = new PrivateKey(key.serialize('test password'), 'test password');
    const restoredPublic = new PublicKey(publicKey.serialize());
    assert.equal(restoredPublic.getLongId(), publicKey.getLongId());
    assert.equal(restoredPublic.checkSignature(payload, restored.sign(payload)), true);
    assert.deepEqual(restored.decrypt(restoredPublic.encrypt(payload)), payload);
    assert.throws(() => new PrivateKey(key.serialize('password'), 'wrong password'));
    assert.throws(() => key.decrypt(Buffer.from('invalid ciphertext')));
    assert.throws(() => key.serialize('bad\0password'), TypeError);
});

test('EC keys sign and invalid crypto inputs raise JS errors', async () => {
    const key = await PrivateKey.generate();
    const restored = new PrivateKey(key.serialize());
    assert.equal(restored.getPublicKey().checkSignature(payload, key.sign(payload)), true);
    assert.throws(() => key.getPublicKey().encrypt(payload));
    for (const Type of [PrivateKey, PublicKey, Certificate]) {
        assert.throws(() => new Type(Buffer.alloc(0)));
        assert.throws(() => new Type(Buffer.from('not a key or certificate')));
        assert.throws(() => new Type(null), TypeError);
    }
    assert.throws(() => PrivateKey.generate({ algorithm: 'unknown' }), TypeError);
    assert.throws(() => PrivateKey.generate({ algorithm: 'rsa', bits: 1 }), RangeError);
    assert.throws(() => PrivateKey.generate({ algorithm: 'rsa', bits: 2048.5 }), RangeError);
    assert.throws(() => key.sign('not bytes'), TypeError);
    assert.throws(() => PrivateKey.prototype.sign.call({}, payload), TypeError);
});

test('identities own matching keys and certificates and support import', async () => {
    const identity = await Identity.generate('nodejs crypto');
    const certificate = new Certificate(identity.certificate.serialize());
    const key = new PrivateKey(identity.privateKey.serialize());
    const restored = new Identity(key, certificate);
    assert.equal(restored.certificate.getLongId(), key.getPublicKey().getLongId());
    assert.equal(certificate.getPublicKey().checkSignature(payload, key.sign(payload)), true);
    assert.throws(() => new Identity({}, certificate), TypeError);
    const other = await PrivateKey.generate();
    assert.throws(() => new Identity(other, certificate), /match/i);
});

test('signed and encrypted values round-trip between authenticated nodes', { timeout: 30000 }, async () => {
    const writerIdentity = await Identity.generate('writer');
    const readerIdentity = await Identity.generate('reader', { algorithm: 'rsa', bits: 2048 });
    const writer = new DhtRunner();
    const reader = new DhtRunner();
    try {
        writer.run({ port: 0, ipv4: '127.0.0.1', ipv6: '::1', identity: writerIdentity });
        reader.run({ port: 0, ipv4: '127.0.0.1', ipv6: '::1', identity: readerIdentity });
        writer.bootstrap('127.0.0.1', reader.getBoundPort());
        reader.bootstrap('127.0.0.1', writer.getBoundPort());
        const signedKey = hash('nodejs signed value');
        assert.equal(await writer.putSigned(signedKey, payload, { id: 41n }), true);
        const signed = await reader.get(signedKey);
        assert.ok(signed.some(value => value.data.equals(payload) && value.isSigned));
        assert.equal(signed[0].owner, writerIdentity.certificate.getLongId());
        const encryptedKey = hash('nodejs encrypted value');
        assert.equal(await writer.putEncrypted(encryptedKey, payload, readerIdentity.certificate.getPublicKey(), { id: 42n }), true);
        const decrypted = await reader.get(encryptedKey);
        assert.ok(decrypted.some(value => value.data.equals(payload)));
        assert.throws(() => writer.putEncrypted(encryptedKey, payload, {}), TypeError);
        assert.throws(() => writer.putEncrypted(encryptedKey, payload, writerIdentity.certificate.getPublicKey()), /RSA/i);
    } finally {
        await Promise.all([writer.close(), reader.close()]);
    }
});

test('signed operations require an identity and reject stopped runners', async () => {
    const runner = new DhtRunner();
    try {
        assert.throws(() => runner.run({ identity: {} }), TypeError);
        runner.run({ port: 0, ipv4: '127.0.0.1', ipv6: '::1' });
        assert.throws(() => runner.putSigned(hash('unsigned'), payload), /identity/i);
    } finally {
        await runner.close();
    }
    assert.throws(() => runner.putSigned(hash('closed'), payload), /closed/i);
});