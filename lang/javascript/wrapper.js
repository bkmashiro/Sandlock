#!/usr/bin/env node
/**
 * Sandlock Node.js Runtime Wrapper
 * 
 * Patches dangerous Node.js APIs before loading user code.
 * Use when vm isolation is too restrictive (need full Node APIs)
 * but want to block specific dangerous operations.
 * 
 * Usage:
 *   node wrapper.js <user_script.js> [args...]
 *   
 * Environment variables:
 *   SANDLOCK_ALLOW_NETWORK=1      Allow network (default: blocked)
 *   SANDLOCK_ALLOW_CHILD=1        Allow child_process (default: blocked)
 *   SANDLOCK_ALLOW_FS_WRITE=1     Allow fs writes outside /tmp
 *   SANDLOCK_ALLOWED_PATHS=/tmp,/var/task
 */

'use strict';

const Module = require('module');
const path = require('path');
const fs = require('fs');

// ============================================================
// Configuration
// ============================================================

const CONFIG = {
    allowNetwork: process.env.SANDLOCK_ALLOW_NETWORK === '1',
    allowChild: process.env.SANDLOCK_ALLOW_CHILD === '1',
    allowFsWrite: process.env.SANDLOCK_ALLOW_FS_WRITE === '1',
    allowedPaths: (process.env.SANDLOCK_ALLOWED_PATHS || '/tmp').split(','),
};

// ============================================================
// Path Checking
// ============================================================

function isPathAllowed(p, forWrite = false) {
    if (!p) return false;
    
    const resolved = path.resolve(p);
    
    // Always allow /tmp for both read and write
    if (resolved.startsWith('/tmp')) return true;
    
    // Check allowed paths
    for (const allowed of CONFIG.allowedPaths) {
        if (resolved.startsWith(path.resolve(allowed))) {
            return true;
        }
    }
    
    // For read operations, allow common system paths
    if (!forWrite) {
        const readAllowed = [
            '/usr/lib', '/usr/share', '/lib',
            '/etc/ssl', '/etc/localtime',
            '/dev/null', '/dev/urandom', '/dev/zero',
        ];
        for (const p of readAllowed) {
            if (resolved.startsWith(p)) return true;
        }
    }
    
    return false;
}

function blockPath(operation, p) {
    const err = new Error(`SANDLOCK: ${operation} blocked for path: ${p}`);
    err.code = 'EACCES';
    throw err;
}

// ============================================================
// Module Blocking
// ============================================================

const BLOCKED_MODULES = new Set([
    // Blocked unless allowed
    'child_process',
    'cluster', 
    'worker_threads',
]);

const NETWORK_MODULES = new Set([
    'net', 'dgram', 'http', 'https', 'http2', 'tls', 'dns',
]);

const originalRequire = Module.prototype.require;

Module.prototype.require = function(id) {
    // Block child process modules
    if (!CONFIG.allowChild && BLOCKED_MODULES.has(id)) {
        throw new Error(`SANDLOCK: Module '${id}' is blocked`);
    }
    
    // Block network modules
    if (!CONFIG.allowNetwork && NETWORK_MODULES.has(id)) {
        throw new Error(`SANDLOCK: Network module '${id}' is blocked`);
    }
    
    // Block native addons that could bypass restrictions
    if (id.includes('.node') || id === 'ffi' || id === 'ffi-napi' || id === 'ref-napi') {
        throw new Error(`SANDLOCK: Native module '${id}' is blocked`);
    }
    
    const result = originalRequire.apply(this, arguments);
    
    // Patch fs module
    if (id === 'fs' || id === 'fs/promises' || id === 'node:fs' || id === 'node:fs/promises') {
        return patchFs(result, id.includes('promises'));
    }
    
    return result;
};

// ============================================================
// FS Patching
// ============================================================

function patchFs(fsModule, isPromises) {
    const patched = Object.create(fsModule);
    
    // Write operations
    const writeOps = [
        'writeFile', 'writeFileSync',
        'appendFile', 'appendFileSync', 
        'mkdir', 'mkdirSync',
        'rmdir', 'rmdirSync',
        'rm', 'rmSync',
        'unlink', 'unlinkSync',
        'rename', 'renameSync',
        'copyFile', 'copyFileSync',
        'symlink', 'symlinkSync',
        'link', 'linkSync',
        'chmod', 'chmodSync',
        'chown', 'chownSync',
        'truncate', 'truncateSync',
    ];
    
    for (const op of writeOps) {
        if (fsModule[op]) {
            const original = fsModule[op];
            if (isPromises) {
                patched[op] = async function(p, ...args) {
                    if (!CONFIG.allowFsWrite && !isPathAllowed(p, true)) {
                        blockPath(op, p);
                    }
                    return original.call(this, p, ...args);
                };
            } else if (op.endsWith('Sync')) {
                patched[op] = function(p, ...args) {
                    if (!CONFIG.allowFsWrite && !isPathAllowed(p, true)) {
                        blockPath(op, p);
                    }
                    return original.call(this, p, ...args);
                };
            } else {
                patched[op] = function(p, ...args) {
                    if (!CONFIG.allowFsWrite && !isPathAllowed(p, true)) {
                        const cb = args[args.length - 1];
                        if (typeof cb === 'function') {
                            const err = new Error(`SANDLOCK: ${op} blocked for path: ${p}`);
                            err.code = 'EACCES';
                            return process.nextTick(() => cb(err));
                        }
                        blockPath(op, p);
                    }
                    return original.call(this, p, ...args);
                };
            }
        }
    }
    
    // Read operations (optional restriction)
    const readOps = [
        'readFile', 'readFileSync',
        'readdir', 'readdirSync',
        'stat', 'statSync',
        'lstat', 'lstatSync',
        'access', 'accessSync',
        'realpath', 'realpathSync',
    ];
    
    for (const op of readOps) {
        if (fsModule[op]) {
            const original = fsModule[op];
            if (isPromises) {
                patched[op] = async function(p, ...args) {
                    if (!isPathAllowed(p, false)) {
                        blockPath(op, p);
                    }
                    return original.call(this, p, ...args);
                };
            } else if (op.endsWith('Sync')) {
                patched[op] = function(p, ...args) {
                    if (!isPathAllowed(p, false)) {
                        blockPath(op, p);
                    }
                    return original.call(this, p, ...args);
                };
            } else {
                patched[op] = function(p, ...args) {
                    if (!isPathAllowed(p, false)) {
                        const cb = args[args.length - 1];
                        if (typeof cb === 'function') {
                            const err = new Error(`SANDLOCK: ${op} blocked for path: ${p}`);
                            err.code = 'EACCES';
                            return process.nextTick(() => cb(err));
                        }
                        blockPath(op, p);
                    }
                    return original.call(this, p, ...args);
                };
            }
        }
    }
    
    // Block createWriteStream/createReadStream for unauthorized paths
    if (fsModule.createWriteStream) {
        patched.createWriteStream = function(p, options) {
            if (!CONFIG.allowFsWrite && !isPathAllowed(p, true)) {
                blockPath('createWriteStream', p);
            }
            return fsModule.createWriteStream.call(this, p, options);
        };
    }
    
    if (fsModule.createReadStream) {
        patched.createReadStream = function(p, options) {
            if (!isPathAllowed(p, false)) {
                blockPath('createReadStream', p);
            }
            return fsModule.createReadStream.call(this, p, options);
        };
    }
    
    return patched;
}

// ============================================================
// Process Patching
// ============================================================

// Block process.binding (access to internal modules)
const originalBinding = process.binding;
process.binding = function(name) {
    // Allow some safe bindings
    const allowed = ['natives', 'config', 'constants'];
    if (!allowed.includes(name)) {
        throw new Error(`SANDLOCK: process.binding('${name}') is blocked`);
    }
    return originalBinding.call(this, name);
};

// Block process._linkedBinding
if (process._linkedBinding) {
    process._linkedBinding = function(name) {
        throw new Error(`SANDLOCK: process._linkedBinding('${name}') is blocked`);
    };
}

// Restrict process.env access (optional - allow read but track)
// const originalEnv = process.env;
// process.env = new Proxy(originalEnv, {
//     get(target, prop) {
//         // Could log or restrict certain env vars
//         return target[prop];
//     }
// });

// ============================================================
// Main
// ============================================================

function main() {
    const args = process.argv.slice(2);
    
    if (args.length === 0 || args[0] === '--help') {
        console.log(`
Sandlock Node.js Wrapper

Usage: node wrapper.js <script.js> [args...]

Environment variables:
  SANDLOCK_ALLOW_NETWORK=1      Allow network modules
  SANDLOCK_ALLOW_CHILD=1        Allow child_process
  SANDLOCK_ALLOW_FS_WRITE=1     Allow fs writes outside /tmp
  SANDLOCK_ALLOWED_PATHS=/tmp,/app   Comma-separated allowed paths
`);
        process.exit(0);
    }
    
    const scriptPath = path.resolve(args[0]);
    
    // Check if script exists and is allowed
    if (!fs.existsSync(scriptPath)) {
        console.error(`Error: Script not found: ${scriptPath}`);
        process.exit(1);
    }
    
    // Update argv to look like the script was run directly
    process.argv = [process.argv[0], scriptPath, ...args.slice(1)];
    
    // Log sandbox config
    if (process.env.SANDLOCK_DEBUG) {
        console.error('[SANDLOCK] Config:', JSON.stringify(CONFIG));
    }
    
    // Run the script
    try {
        require(scriptPath);
    } catch (err) {
        if (err.message.startsWith('SANDLOCK:')) {
            console.error(`Security violation: ${err.message}`);
            process.exit(1);
        }
        throw err;
    }
}

main();
