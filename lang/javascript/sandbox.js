#!/usr/bin/env node
/**
 * Sandlock JavaScript Sandbox
 * Language-level restrictions for Lambda environments.
 * 
 * Usage:
 *   node sandbox.js <code_file> [--timeout N] [--memory MB] [--json]
 */

const vm = require('vm');
const fs = require('fs');
const path = require('path');

// ============================================================
// Configuration
// ============================================================

const BLOCKED_MODULES = new Set([
    // Network
    'net', 'dgram', 'http', 'https', 'http2', 'tls', 'dns',
    
    // Process/System
    'child_process', 'cluster', 'worker_threads',
    'os', 'process',
    
    // Filesystem (allow limited)
    // 'fs', 'path' - restricted versions provided
    
    // Low-level
    'v8', 'perf_hooks', 'async_hooks', 'trace_events',
    'inspector', 'repl',
    
    // Native
    'ffi', 'ffi-napi', 'ref', 'ref-napi',
]);

const ALLOWED_MODULES = new Set([
    // Safe built-ins
    'assert', 'buffer', 'crypto', 'events', 'querystring',
    'string_decoder', 'url', 'util', 'zlib', 'stream',
    'timers', 'console',
]);

// ============================================================
// Restricted APIs
// ============================================================

class RestrictedFS {
    constructor(workdir = '/tmp') {
        this.workdir = path.resolve(workdir);
    }
    
    _checkPath(p) {
        const resolved = path.resolve(this.workdir, p);
        if (!resolved.startsWith(this.workdir) && !resolved.startsWith('/tmp')) {
            throw new Error(`Access denied: ${p} (only ${this.workdir} allowed)`);
        }
        return resolved;
    }
    
    readFileSync(p, options) {
        return fs.readFileSync(this._checkPath(p), options);
    }
    
    writeFileSync(p, data, options) {
        const resolved = this._checkPath(p);
        if (!resolved.startsWith('/tmp')) {
            throw new Error(`Write access denied: ${p}`);
        }
        return fs.writeFileSync(resolved, data, options);
    }
    
    existsSync(p) {
        try {
            this._checkPath(p);
            return fs.existsSync(this._checkPath(p));
        } catch {
            return false;
        }
    }
    
    readdirSync(p) {
        return fs.readdirSync(this._checkPath(p));
    }
    
    statSync(p) {
        return fs.statSync(this._checkPath(p));
    }
    
    mkdirSync(p, options) {
        const resolved = this._checkPath(p);
        if (!resolved.startsWith('/tmp')) {
            throw new Error(`Write access denied: ${p}`);
        }
        return fs.mkdirSync(resolved, options);
    }
    
    unlinkSync(p) {
        const resolved = this._checkPath(p);
        if (!resolved.startsWith('/tmp')) {
            throw new Error(`Delete access denied: ${p}`);
        }
        return fs.unlinkSync(resolved);
    }
}

function createRestrictedRequire(workdir) {
    const restrictedFs = new RestrictedFS(workdir);
    
    return function restrictedRequire(moduleName) {
        // Block dangerous modules
        if (BLOCKED_MODULES.has(moduleName)) {
            throw new Error(`Module '${moduleName}' is blocked`);
        }
        
        // Provide restricted fs
        if (moduleName === 'fs') {
            return restrictedFs;
        }
        
        // Provide safe path
        if (moduleName === 'path') {
            return {
                join: path.join,
                resolve: (...args) => {
                    const resolved = path.resolve(...args);
                    if (!resolved.startsWith('/tmp') && !resolved.startsWith(workdir)) {
                        throw new Error(`Path access denied: ${resolved}`);
                    }
                    return resolved;
                },
                basename: path.basename,
                dirname: path.dirname,
                extname: path.extname,
                parse: path.parse,
                format: path.format,
                normalize: path.normalize,
                isAbsolute: path.isAbsolute,
                relative: path.relative,
                sep: path.sep,
            };
        }
        
        // Allow safe modules
        if (ALLOWED_MODULES.has(moduleName)) {
            return require(moduleName);
        }
        
        // Block unknown modules
        throw new Error(`Module '${moduleName}' is not in whitelist`);
    };
}

// ============================================================
// Sandbox Context
// ============================================================

function createSandboxContext(workdir = '/tmp') {
    const restrictedRequire = createRestrictedRequire(workdir);
    
    // Safe console
    const safeConsole = {
        log: (...args) => console.log(...args),
        error: (...args) => console.error(...args),
        warn: (...args) => console.warn(...args),
        info: (...args) => console.info(...args),
        debug: (...args) => console.debug(...args),
        time: console.time.bind(console),
        timeEnd: console.timeEnd.bind(console),
    };
    
    // Safe globals
    const context = {
        // Core
        console: safeConsole,
        require: restrictedRequire,
        
        // Types
        Array, Object, String, Number, Boolean, Symbol, BigInt,
        Date, RegExp, Error, TypeError, RangeError, SyntaxError,
        Map, Set, WeakMap, WeakSet,
        Promise, Proxy, Reflect,
        
        // Functions
        parseInt, parseFloat, isNaN, isFinite,
        encodeURI, decodeURI, encodeURIComponent, decodeURIComponent,
        JSON, Math,
        
        // Async
        setTimeout: (fn, ms) => setTimeout(fn, Math.min(ms, 5000)),
        setInterval: (fn, ms) => setInterval(fn, Math.min(ms, 5000)),
        clearTimeout,
        clearInterval,
        setImmediate,
        clearImmediate,
        
        // Buffer (limited)
        Buffer: {
            from: Buffer.from,
            alloc: (size) => {
                if (size > 10 * 1024 * 1024) {
                    throw new Error('Buffer too large (max 10MB)');
                }
                return Buffer.alloc(size);
            },
            allocUnsafe: (size) => {
                if (size > 10 * 1024 * 1024) {
                    throw new Error('Buffer too large (max 10MB)');
                }
                return Buffer.allocUnsafe(size);
            },
            isBuffer: Buffer.isBuffer,
            concat: Buffer.concat,
        },
        
        // Module simulation
        module: { exports: {} },
        exports: {},
        __dirname: workdir,
        __filename: path.join(workdir, 'sandbox.js'),
    };
    
    // Remove dangerous globals
    context.process = undefined;
    context.global = undefined;
    context.globalThis = context;
    context.eval = undefined;
    context.Function = undefined;
    
    return context;
}

// ============================================================
// Execution
// ============================================================

async function runSandboxed(code, options = {}) {
    const {
        timeout = 5000,
        memoryLimit = 256,  // MB (informational, not enforced by VM)
        workdir = '/tmp',
    } = options;
    
    const result = {
        success: true,
        output: '',
        error: null,
    };
    
    // Capture console output
    const outputs = [];
    const originalLog = console.log;
    const originalError = console.error;
    
    const context = createSandboxContext(workdir);
    context.console.log = (...args) => outputs.push(args.map(String).join(' '));
    context.console.error = (...args) => outputs.push('[ERROR] ' + args.map(String).join(' '));
    
    vm.createContext(context);
    
    try {
        const script = new vm.Script(code, {
            filename: 'sandbox.js',
            timeout: timeout,
        });
        
        await script.runInContext(context, {
            timeout: timeout,
            breakOnSigint: true,
        });
        
        result.output = outputs.join('\n');
        
    } catch (err) {
        result.success = false;
        
        if (err.code === 'ERR_SCRIPT_EXECUTION_TIMEOUT') {
            result.error = 'Execution timed out';
        } else if (err.message.includes('blocked') || err.message.includes('denied')) {
            result.error = `Blocked: ${err.message}`;
        } else {
            result.error = `${err.name}: ${err.message}`;
        }
    } finally {
        console.log = originalLog;
        console.error = originalError;
    }
    
    return result;
}

// ============================================================
// CLI
// ============================================================

async function main() {
    const args = process.argv.slice(2);
    
    if (args.length === 0 || args.includes('--help')) {
        console.log(`
Sandlock JavaScript Sandbox

Usage: node sandbox.js <code_file> [options]

Options:
  --timeout N    Timeout in milliseconds (default: 5000)
  --memory MB    Memory limit hint in MB (default: 256)
  --workdir DIR  Working directory (default: /tmp)
  --json         Output as JSON
  --help         Show this help
`);
        process.exit(0);
    }
    
    const codeFile = args[0];
    const jsonOutput = args.includes('--json');
    
    let timeout = 5000;
    let memory = 256;
    let workdir = '/tmp';
    
    for (let i = 1; i < args.length; i++) {
        if (args[i] === '--timeout' && args[i + 1]) {
            timeout = parseInt(args[++i], 10);
        } else if (args[i] === '--memory' && args[i + 1]) {
            memory = parseInt(args[++i], 10);
        } else if (args[i] === '--workdir' && args[i + 1]) {
            workdir = args[++i];
        }
    }
    
    // Read code
    let code;
    try {
        code = fs.readFileSync(codeFile, 'utf8');
    } catch (err) {
        const result = { success: false, output: '', error: `Cannot read file: ${codeFile}` };
        if (jsonOutput) {
            console.log(JSON.stringify(result));
        } else {
            console.error(result.error);
        }
        process.exit(1);
    }
    
    // Execute
    const result = await runSandboxed(code, { timeout, memoryLimit: memory, workdir });
    
    if (jsonOutput) {
        console.log(JSON.stringify(result));
    } else {
        if (result.output) {
            process.stdout.write(result.output);
            if (!result.output.endsWith('\n')) {
                process.stdout.write('\n');
            }
        }
        if (result.error) {
            console.error(`Error: ${result.error}`);
        }
        process.exit(result.success ? 0 : 1);
    }
}

main().catch(err => {
    console.error(err);
    process.exit(1);
});
