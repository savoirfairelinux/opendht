import { Buffer } from 'node:buffer';
import { EventEmitter } from 'node:events';

export const version: string;
export function hash(data: string | Uint8Array): string;

export interface KeyOptions {
    algorithm?: 'ec' | 'rsa';
    bits?: number;
}

export class PublicKey {
    constructor(data: Uint8Array);
    serialize(): Buffer;
    getId(): string;
    getLongId(): string;
    checkSignature(data: Uint8Array, signature: Uint8Array): boolean;
    encrypt(data: Uint8Array): Buffer;
}

export class PrivateKey {
    constructor(data: Uint8Array, password?: string);
    static generate(options?: KeyOptions): Promise<PrivateKey>;
    serialize(password?: string): Buffer;
    getPublicKey(): PublicKey;
    sign(data: Uint8Array): Buffer;
    decrypt(data: Uint8Array): Buffer;
}

export class Certificate {
    constructor(data: Uint8Array);
    serialize(): Buffer;
    getPublicKey(): PublicKey;
    getId(): string;
    getLongId(): string;
}

export class Identity {
    constructor(privateKey: PrivateKey, certificate: Certificate);
    static generate(name?: string, options?: KeyOptions): Promise<Identity>;
    readonly privateKey: PrivateKey;
    readonly certificate: Certificate;
}

export interface RunOptions {
    port?: number;
    ipv4?: string;
    ipv6?: string;
    network?: number;
    persistPath?: string;
    identity?: Identity;
}

export interface PutOptions {
    id?: bigint;
    type?: number;
    userType?: string;
    permanent?: boolean;
}

export interface Value {
    id: bigint;
    type: number;
    seq: number;
    data: Buffer;
    userType: string;
    owner: string | null;
    isSigned: boolean;
    isEncrypted: boolean;
}

export interface Listener {
    cancel(): void;
}

export class DhtRunner extends EventEmitter implements AsyncDisposable {
    run(options?: RunOptions): void;
    isRunning(): boolean;
    getBoundPort(family?: 4 | 6): number;
    getNodeId(): string;
    bootstrap(host: string, port: number): void;
    get(key: string): Promise<Value[]>;
    put(key: string, data: Uint8Array, options?: PutOptions): Promise<boolean>;
    putSigned(key: string, data: Uint8Array, options?: PutOptions): Promise<boolean>;
    putEncrypted(key: string, data: Uint8Array, recipient: PublicKey, options?: PutOptions): Promise<boolean>;
    listen(key: string, callback: (value: Value, expired: boolean) => void): Listener;
    close(): Promise<void>;
    ref(): this;
    unref(): this;
    [Symbol.asyncDispose](): Promise<void>;
}