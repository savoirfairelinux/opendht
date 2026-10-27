export default function createCrypto(native) {
    const handles = new WeakMap();

    function handle(value, Type) {
        if (!(value instanceof Type) || !handles.has(value)) throw new TypeError(`Expected ${Type.name}`);
        return handles.get(value);
    }

    function wrap(Type, nativeHandle) {
        const result = Object.create(Type.prototype);
        handles.set(result, nativeHandle);
        return result;
    }

    function generate(kind, name, options = {}) {
        if (!options || typeof options !== 'object' || Array.isArray(options)) throw new TypeError('Invalid crypto options');
        return native.cryptoGenerate(kind, name, options.algorithm ?? 'ec', options.bits ?? 2048);
    }

    class PublicKey {
        constructor(data) { handles.set(this, native.cryptoImport('public', data)); }
        serialize() { return native.cryptoSerialize(handle(this, PublicKey)); }
        getId() { return native.cryptoId(handle(this, PublicKey), false); }
        getLongId() { return native.cryptoId(handle(this, PublicKey), true); }
        checkSignature(data, signature) { return native.cryptoVerify(handle(this, PublicKey), data, signature); }
        encrypt(data) { return native.cryptoEncrypt(handle(this, PublicKey), data); }
    }

    class PrivateKey {
        constructor(data, password = '') { handles.set(this, native.cryptoImport('private', data, password)); }
        static generate(options) { return generate('private', '', options).then(value => wrap(PrivateKey, value)); }
        serialize(password = '') { return native.cryptoSerialize(handle(this, PrivateKey), password); }
        getPublicKey() { return wrap(PublicKey, native.cryptoPublicKey(handle(this, PrivateKey))); }
        sign(data) { return native.cryptoSign(handle(this, PrivateKey), data); }
        decrypt(data) { return native.cryptoDecrypt(handle(this, PrivateKey), data); }
    }

    class Certificate {
        constructor(data) { handles.set(this, native.cryptoImport('certificate', data)); }
        serialize() { return native.cryptoSerialize(handle(this, Certificate)); }
        getPublicKey() { return wrap(PublicKey, native.cryptoPublicKey(handle(this, Certificate))); }
        getId() { return native.cryptoId(handle(this, Certificate), false); }
        getLongId() { return native.cryptoId(handle(this, Certificate), true); }
    }

    class Identity {
        constructor(privateKey, certificate) {
            handles.set(this, native.cryptoIdentity(handle(privateKey, PrivateKey), handle(certificate, Certificate)));
        }
        static generate(name = 'dhtnode', options) { return generate('identity', name, options).then(value => wrap(Identity, value)); }
        get privateKey() { return wrap(PrivateKey, native.cryptoIdentityPart(handle(this, Identity), true)); }
        get certificate() { return wrap(Certificate, native.cryptoIdentityPart(handle(this, Identity), false)); }
    }

    return { PublicKey, PrivateKey, Certificate, Identity, handle };
}