import { Certificate, ConnectivityStatus, DhtRunner, Identity, NodeStatus, PrivateKey, PublicKey, hash, Value, version } from '..';

async function exercise(): Promise<void> {
    const privateKey: PrivateKey = await PrivateKey.generate({ algorithm: 'rsa', bits: 2048 });
    const publicKey: PublicKey = new PublicKey(privateKey.getPublicKey().serialize());
    const identity: Identity = await Identity.generate('typed identity');
    const restored = new Identity(identity.privateKey, new Certificate(identity.certificate.serialize()));
    const valid: boolean = publicKey.checkSignature(Buffer.alloc(0), privateKey.sign(Buffer.alloc(0)));
    const plaintext: Buffer = privateKey.decrypt(publicKey.encrypt(Buffer.from('secret')));
    const runner = new DhtRunner();
    runner.on('error', (error: Error) => { throw error; });
    runner.on('statusChanged', status => {
        const ipv4: NodeStatus = status.ipv4;
        const ipv6: NodeStatus = status.ipv6;
        void [ipv4, ipv6];
    });
    const status: ConnectivityStatus = runner.getStatus();
    runner.run({ port: 0, network: 1, persistPath: '', identity: restored });
    runner.bootstrap('127.0.0.1', runner.getBoundPort(4));
    const key: string = hash(new Uint8Array([0, 255]));
    const accepted: boolean = await runner.put(key, Buffer.from(version), { id: 42n, permanent: true });
    const signed: boolean = await runner.putSigned(key, plaintext);
    const encrypted: boolean = await runner.putEncrypted(key, plaintext, publicKey);
    const values: Value[] = await runner.get(key);
    const listener = runner.listen(key, (value, expired) => {
        const payload: Buffer = value.data;
        const id: bigint = value.id;
        void [payload, id, expired];
    });
    runner.ref().unref();
    listener.cancel();
    await runner[Symbol.asyncDispose]();
    void [accepted, values, valid, signed, encrypted, status];
}

void exercise;