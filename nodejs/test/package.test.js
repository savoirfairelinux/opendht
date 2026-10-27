import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import path from 'node:path';
import { test } from 'node:test';

const root = path.resolve(import.meta.dirname, '..');

test('package exposes ESM-only named exports', () => {
    const manifest = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
    assert.equal(manifest.type, 'module');
    assert.equal(manifest.exports['.'].import, './index.js');
    assert.equal(manifest.exports['.'].require, undefined);
    const stdout = execFileSync(process.execPath, ['--input-type=module', '-e', `
        import { DhtRunner, hash } from ${JSON.stringify(manifest.name)};
        console.log(hash('hello'));
        const runner = new DhtRunner();
        await runner.close();
    `], { cwd: root, encoding: 'utf8' });
    assert.equal(stdout.trim(), 'aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d');
});

test('npm archive contains runtime files and excludes development artifacts', () => {
    const npm = process.env.npm_execpath;
    assert.ok(npm, 'Run the package contract with npm test');
    const [archive] = JSON.parse(execFileSync(process.execPath,
        [npm, 'pack', '--dry-run', '--json', '--ignore-scripts'],
        { cwd: root, encoding: 'utf8' }));
    const files = archive.files.map(file => file.path);
    for (const file of ['index.js', 'index.d.ts', 'crypto.js', 'README.md', 'examples/dhtnode.js', 'examples/dhtnode.ts']) assert.ok(files.includes(file), file);
    assert.equal(files.some(file => /^(build[^/]*|node_modules|test|scripts)\//.test(file)), false);
    assert.equal(files.some(file => /\.(cpp|h|tsbuildinfo)$/.test(file)), false);
    assert.ok(files.every(file => /^(index\.js|index\.d\.ts|crypto\.js|README\.md|package\.json|examples\/dhtnode\.(js|ts)|prebuilds\/)/.test(file)));
});