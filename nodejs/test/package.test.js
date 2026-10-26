'use strict';

const assert = require('node:assert/strict');
const { execFileSync } = require('node:child_process');
const path = require('node:path');
const { test } = require('node:test');

test('npm archive contains runtime files and excludes development artifacts', () => {
    const npm = process.env.npm_execpath;
    assert.ok(npm, 'Run the package contract with npm test');
    const [archive] = JSON.parse(execFileSync(process.execPath,
        [npm, 'pack', '--dry-run', '--json', '--ignore-scripts'],
        { cwd: path.resolve(__dirname, '..'), encoding: 'utf8' }));
    const files = archive.files.map(file => file.path);
    for (const file of ['index.js', 'index.d.ts', 'crypto.js', 'README.md', 'examples/dhtnode.js']) assert.ok(files.includes(file), file);
    assert.equal(files.some(file => /^(build[^/]*|node_modules|test|scripts)\//.test(file)), false);
    assert.equal(files.some(file => /\.(cpp|h|tsbuildinfo)$/.test(file)), false);
    assert.ok(files.every(file => /^(index\.js|index\.d\.ts|crypto\.js|README\.md|package\.json|examples\/dhtnode\.js|prebuilds\/)/.test(file)));
});