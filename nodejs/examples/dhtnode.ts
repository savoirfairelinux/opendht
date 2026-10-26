#!/usr/bin/env node
'use strict';

import { clearLine, createInterface, cursorTo, type Interface } from 'node:readline';
import { parseArgs } from 'node:util';
import type { ConnectivityStatus, Listener, Value } from '../index.js';

const commands = 'get KEY | put KEY TEXT | sign KEY TEXT | listen KEY | cancel KEY | help | quit';

function portNumber(value: string, name: string, minimum = 0): number {
    const port = Number(value);
    if (!Number.isInteger(port) || port < minimum || port > 65535) {
        throw new Error(`${name} must be an integer between ${minimum} and 65535`);
    }
    return port;
}

function errorMessage(error: unknown): string {
    return error instanceof Error ? error.message : String(error);
}

function report(error: unknown): void {
    console.error(errorMessage(error));
    process.exitCode = 1;
}

async function main(): Promise<void> {
    const { values } = parseArgs({
        options: {
            help: { type: 'boolean', short: 'h' },
            port: { type: 'string', short: 'p', default: '4222' },
            ipv4: { type: 'string', default: '0.0.0.0' },
            ipv6: { type: 'string', default: '::' },
            bootstrap: { type: 'string', short: 'b' },
            'bootstrap-port': { type: 'string', default: '4222' },
        },
    });
    if (values.help) {
        console.log(`Usage: npm run dhtnode -- [options]

  -p, --port PORT           Local UDP port (default: 4222; 0 selects a free port)
  -b, --bootstrap HOST      Optional bootstrap hostname or IP address
      --bootstrap-port PORT  Bootstrap UDP port (default: 4222)
      --ipv4 ADDRESS       IPv4 bind address (default: 0.0.0.0)
      --ipv6 ADDRESS       IPv6 bind address (default: ::)
  -h, --help               Show help

Commands: ${commands}
Keys are text labels hashed with SHA-1. Values are UTF-8 text.`);
        return;
    }
    const port = portNumber(values.port, 'port');
    const bootstrapPort = portNumber(values['bootstrap-port'], 'bootstrap-port', 1);
    const { DhtRunner, Identity, hash }: typeof import('../index.js') = require('..');
    const identity = await Identity.generate('dhtnode.ts');
    const runner = new DhtRunner();
    const listeners = new Map<string, Listener>();
    const pending = new Set<Promise<void>>();
    let lines: Interface | undefined;
    let closing: Promise<void> | undefined;

    function close(): Promise<void> {
        if (!closing) {
            for (const listener of listeners.values()) listener.cancel();
            listeners.clear();
            lines?.close();
            closing = runner.close();
        }
        return closing;
    }

    function print(message: string): void {
        if (process.stdout.isTTY && lines) {
            clearLine(process.stdout, 0);
            cursorTo(process.stdout, 0);
        }
        console.log(message);
        if (!closing && process.stdin.isTTY) lines?.prompt(true);
    }

    const stop = (): void => { close().catch(report); };
    const printValue = (label: string, value: Value): void => {
        print(`${label} ${value.id}: ${JSON.stringify(value.data.toString('utf8'))}${value.isSigned ? ' [signed]' : ''}`);
    };
    const printStatus = (status: ConnectivityStatus): void => {
        print(`Connectivity: IPv4 ${status.ipv4}, IPv6 ${status.ipv6}`);
    };

    async function execute(line: string): Promise<void> {
        const [, command, key, data] = line.trim().match(/^(\S+)(?:\s+(\S+))?(?:\s+(.+))?$/) || [];
        if (!command) return;
        if (command === 'help') {
            print(commands);
            return;
        }
        if (!key) throw new Error('Expected a key. Type help for commands.');
        const location = hash(key);
        switch (command) {
            case 'get': {
                const found = await runner.get(location);
                if (closing) return;
                for (const value of found) printValue(key, value);
                if (!found.length) print(`No values for ${key}`);
                break;
            }
            case 'put':
            case 'sign': {
                if (data === undefined) throw new Error(`Usage: ${command} KEY TEXT`);
                const payload = Buffer.from(data, 'utf8');
                const ok = command === 'sign' ? await runner.putSigned(location, payload)
                    : await runner.put(location, payload);
                if (closing) return;
                if (!ok) throw new Error(`Put failed for ${key}`);
                print(`Stored ${key}`);
                break;
            }
            case 'listen':
                if (!listeners.has(key)) {
                    listeners.set(key, runner.listen(location, (value, expired) => {
                        printValue(`${expired ? 'Expired' : 'Value'} ${key}`, value);
                    }));
                }
                print(`Listening ${key}`);
                break;
            case 'cancel':
                listeners.get(key)?.cancel();
                listeners.delete(key);
                print(`Cancelled ${key}`);
                break;
            default:
                throw new Error('Unknown command. Type help for commands.');
        }
    }

    runner.on('error', error => { report(error); stop(); });
    runner.on('statusChanged', printStatus);
    process.on('SIGINT', stop);
    process.on('SIGTERM', stop);
    try {
        runner.run({ port, ipv4: values.ipv4, ipv6: values.ipv6, identity });
        if (values.bootstrap) runner.bootstrap(values.bootstrap, bootstrapPort);
        lines = createInterface({ input: process.stdin, output: process.stdout });
        lines.on('SIGINT', stop);
        lines.setPrompt('dht> ');
        print(`Node ${runner.getNodeId()} listening on UDP ${runner.getBoundPort()}`);
        printStatus(runner.getStatus());
        if (process.stdin.isTTY) print(commands);
        for await (const line of lines) {
            if (closing) break;
            if (/^(quit|exit)(?:\s|$)/.test(line.trim())) {
                stop();
                break;
            }
            const operation = execute(line).catch(error => {
                if (!closing) console.error(errorMessage(error));
            }).finally(() => { pending.delete(operation); });
            pending.add(operation);
            if (process.stdin.isTTY) lines.prompt();
        }
        if (!closing) await Promise.all(pending);
    } finally {
        try {
            await close();
            await Promise.all(pending);
        } finally {
            process.removeListener('SIGINT', stop);
            process.removeListener('SIGTERM', stop);
        }
    }
}

main().catch(report);