import { DhtRunner, hash, Value, version } from '..';

async function exercise(): Promise<void> {
    const runner = new DhtRunner();
    runner.on('error', (error: Error) => { throw error; });
    runner.run({ port: 0, network: 1, persistPath: '' });
    runner.bootstrap('127.0.0.1', runner.getBoundPort(4));
    const key: string = hash(new Uint8Array([0, 255]));
    const accepted: boolean = await runner.put(key, Buffer.from(version), { id: 42n, permanent: true });
    const values: Value[] = await runner.get(key);
    const listener = runner.listen(key, (value, expired) => {
        const payload: Buffer = value.data;
        const id: bigint = value.id;
        void [payload, id, expired];
    });
    runner.ref().unref();
    listener.cancel();
    await runner[Symbol.asyncDispose]();
    void [accepted, values];
}

void exercise;