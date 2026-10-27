import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

const root = path.resolve(import.meta.dirname, '..');
const npm = process.env.npm_execpath;
if (!npm) throw new Error('Run this check with npm run test:package');
fs.mkdirSync(path.join(root, 'dist'), { recursive: true });
let archive = process.argv[2] ? path.resolve(process.argv[2]) : path.join(root, 'dist',
    JSON.parse(execFileSync(process.execPath, [npm, 'pack', '--json', '--pack-destination', 'dist'],
        { cwd: root, encoding: 'utf8' }))[0].filename);
if (fs.statSync(archive).isDirectory()) {
    const archives = fs.readdirSync(archive).filter(file => file.endsWith('.tgz'));
    if (archives.length !== 1) throw new Error('Expected exactly one npm archive');
    archive = path.join(archive, archives[0]);
}
const consumer = fs.mkdtempSync(path.join(os.tmpdir(), 'opendht-consumer-'));
const env = { ...process.env, PREBUILDS_ONLY: '1' };
for (const variable of ['OPENDHT_NODE_BINDING', 'NODE_PATH', 'LD_LIBRARY_PATH', 'DYLD_LIBRARY_PATH', 'DYLD_FALLBACK_LIBRARY_PATH']) delete env[variable];
const excluded = [path.join(root, 'build'), ...(process.env.OPENDHT_LIBRARY_PATH || '').split(path.delimiter).filter(Boolean)];
const pathKey = Object.keys(env).find(key => key.toLowerCase() === 'path');
if (pathKey) env[pathKey] = env[pathKey].split(path.delimiter)
    .filter(entry => !excluded.some(directory => path.resolve(entry).toLowerCase().startsWith(path.resolve(directory).toLowerCase())))
    .join(path.delimiter);
try {
    execFileSync(process.execPath, [npm, 'install', '--prefix', consumer, '--ignore-scripts', '--omit=dev', '--no-audit', '--no-fund', archive],
        { cwd: consumer, env, stdio: 'inherit' });
    const { name } = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf8'));
    const installed = path.join(consumer, 'node_modules', ...name.split('/'));
    execFileSync(process.execPath, ['--input-type=module', '-e', 'import load from "node-gyp-build"; console.log(load.path(process.cwd()))'],
        { cwd: installed, env, stdio: 'inherit' });
    fs.cpSync(path.join(root, 'test'), path.join(installed, 'test'), { recursive: true });
    execFileSync(process.execPath, [npm, 'test'], { cwd: installed, env, stdio: 'inherit' });
    console.log(`Installed archive verified: ${archive}`);
} finally {
    fs.rmSync(consumer, { recursive: true, force: true });
}