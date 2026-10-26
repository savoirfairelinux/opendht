import { Buffer } from 'node:buffer';
import { EventEmitter } from 'node:events';

export const version: string;
export function hash(data: string | Uint8Array): string;

export interface RunOptions {
    port?: number;
    ipv4?: string;
    ipv6?: string;
    network?: number;
    persistPath?: string;
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
    listen(key: string, callback: (value: Value, expired: boolean) => void): Listener;
    close(): Promise<void>;
    ref(): this;
    unref(): this;
    [Symbol.asyncDispose](): Promise<void>;
}