'use strict';

const { execFileSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');

const root = path.resolve(__dirname, '..');
const repository = path.dirname(root);
const input = path.resolve(process.argv[2] || path.join(root, 'build/Release/opendht.node'));
const target = `${process.platform}-${process.arch}`;
const output = path.join(root, 'prebuilds', target);
const temporary = fs.mkdtempSync(path.join(os.tmpdir(), 'opendht-bundle-'));
const run = (command, args) => execFileSync(command, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'inherit'] });

function copyNotices(dependencies) {
    const directory = path.join(output, 'licenses');
    fs.mkdirSync(directory, { recursive: true });
    fs.copyFileSync(path.join(repository, 'LICENSE'), path.join(directory, 'OpenDHT-LICENSE.txt'));
    const copied = new Set();
    for (const dependency of dependencies) {
        const real = fs.realpathSync(dependency);
        if (!path.relative(repository, real).startsWith('..')) continue;
        let name;
        let notices;
        if (process.platform === 'darwin') {
            const match = real.match(/^(.*\/Cellar\/([^/]+)\/[^/]+)\//);
            if (!match) throw new Error(`Cannot locate license notices for ${dependency}`);
            name = match[2];
            notices = fs.readdirSync(match[1]).filter(file => /^(COPYING|LICENSE|COPYRIGHT)([._-]|$)/i.test(file))
                .map(file => path.join(match[1], file));
        } else if (process.platform === 'linux') {
            let owner;
            try { owner = run('dpkg-query', ['-S', real]); }
            catch { owner = run('dpkg-query', ['-S', real.replace(/^\/usr\//, '/')]); }
            name = owner.split('\n')[0].split(': ')[0].split(':')[0];
            notices = [path.join('/usr/share/doc', name, 'copyright')];
        } else {
            const installed = process.env.VCPKG_INSTALLED_DIR;
            const triplet = process.env.VCPKG_DEFAULT_TRIPLET || 'x64-windows-release';
            if (!installed) throw new Error('VCPKG_INSTALLED_DIR is required for Windows dependency notices');
            const share = path.join(installed, triplet, 'share');
            for (const entry of fs.readdirSync(share)) {
                const copyright = path.join(share, entry, 'copyright');
                if (fs.existsSync(copyright)) fs.copyFileSync(copyright, path.join(directory, `${entry}-copyright.txt`));
            }
            break;
        }
        if (!notices.length) throw new Error(`Missing license notices for ${name}`);
        if (copied.has(name)) continue;
        for (const notice of notices) fs.copyFileSync(notice, path.join(directory, `${name}-${path.basename(notice)}.txt`));
        copied.add(name);
    }
}

function fixMachO(file) {
    const commands = run('otool', ['-l', file]);
    const rpaths = [...commands.matchAll(/cmd LC_RPATH\s+cmdsize \d+\s+path (.+?) \(offset \d+\)/g)];
    for (const rpath of new Set(rpaths.map(match => match[1]))) run('install_name_tool', ['-delete_rpath', rpath, file]);
    const dependencies = [...run('otool', ['-L', file]).matchAll(/^\s+(.+?) \(compatibility version/gm)];
    for (const [, dependency] of dependencies) {
        if (!/^(@loader_path\/|\/usr\/lib\/|\/System\/Library\/)/.test(dependency)) {
            throw new Error(`Non-relocatable dependency in ${path.basename(file)}: ${dependency}`);
        }
    }
    run('codesign', ['--force', '--sign', '-', file]);
}

try {
    if (!['darwin', 'linux', 'win32'].includes(process.platform)) throw new Error(`Unsupported platform ${target}`);
    if (!fs.existsSync(input)) throw new Error(`Build the Release addon first: ${input}`);
    if (process.platform === 'linux' && !process.report.getReport().header.glibcVersionRuntime) {
        throw new Error('Linux prebuilds currently require glibc');
    }
    const directories = [path.dirname(input), ...(process.env.OPENDHT_LIBRARY_PATH || '').split(path.delimiter).filter(Boolean)];
    const dependencyList = path.join(temporary, 'dependencies.json');
    run('cmake', [`-DADDON=${input}`, `-DOUTPUT=${dependencyList}`, `-DSEARCH_DIRECTORIES=${directories.join(';')}`,
        '-P', path.join(__dirname, 'dependencies.cmake')]);
    const dependencies = JSON.parse(fs.readFileSync(dependencyList, 'utf8'));
    fs.rmSync(output, { recursive: true, force: true });
    fs.mkdirSync(output, { recursive: true });
    const binary = path.join(output, process.platform === 'linux' ? 'node.napi.glibc.node' : 'node.napi.node');
    fs.copyFileSync(input, binary);
    if (process.platform === 'darwin') {
        run('dylibbundler', ['-b', '-of', '-ns', '-x', binary, '-d', `${output}/`, '-p', '@loader_path/', '-s', path.dirname(input)]);
        for (const file of fs.readdirSync(output)) fixMachO(path.join(output, file));
    } else {
        for (const dependency of dependencies) fs.copyFileSync(dependency, path.join(output, path.basename(dependency)));
        if (process.platform === 'linux') {
            for (const file of fs.readdirSync(output)) run('patchelf', ['--set-rpath', '$ORIGIN', path.join(output, file)]);
        }
    }
    copyNotices(dependencies);
    fs.writeFileSync(path.join(output, 'manifest.json'), JSON.stringify({
        platform: process.platform,
        arch: process.arch,
        napi: 8,
        libraries: fs.readdirSync(output).filter(file => /\.(node|dll|dylib)$|\.so(\.|$)/.test(file)).sort(),
    }, null, 2) + '\n');
    fs.mkdirSync(path.join(root, 'dist'), { recursive: true });
    console.log(`Bundled ${target}: ${output}`);
} finally {
    fs.rmSync(temporary, { recursive: true, force: true });
}