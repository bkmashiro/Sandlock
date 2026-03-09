# Language-Specific Sandboxes

For environments where kernel-level sandboxing (seccomp, Landlock) is unavailable (e.g., AWS Lambda), these language-specific wrappers provide application-level isolation.

## Available Languages

| Language | File | Status | Bypass Risk |
|----------|------|:------:|:-----------:|
| Python | `python/sandbox.py` | ✅ | Low |
| JavaScript | `javascript/sandbox.js` | ✅ | Low |
| LD_PRELOAD | `preload/sandbox_preload.so` | ✅ | High |
| Java | `java/Sandbox.java` | 🚧 TODO | - |

## Python Sandbox

### Usage

```bash
# Basic
python3 lang/python/sandbox.py student_code.py

# With options
python3 lang/python/sandbox.py code.py --timeout 10 --memory 128 --workdir /tmp/sandbox

# JSON output
python3 lang/python/sandbox.py code.py --json
```

### Defenses

| Attack | Blocked | Method |
|--------|:-------:|--------|
| `import socket` | ✅ | Import hook |
| `import os` | ✅ | Import hook |
| `subprocess.run()` | ✅ | Import hook |
| `ctypes` syscall | ✅ | Import hook |
| `open('/etc/passwd')` | ✅ | Restricted open |
| `eval()` / `exec()` | ✅ | Removed from builtins |
| CPU exhaustion | ✅ | RLIMIT_CPU |
| Memory exhaustion | ✅ | RLIMIT_AS |
| Large file write | ✅ | RLIMIT_FSIZE |

### Allowed Modules

```
math, cmath, decimal, fractions, random, statistics
json, csv, re, string, textwrap
collections, heapq, bisect, array
itertools, functools, operator
datetime, time, calendar
typing, types, copy, pprint
base64, binascii, hashlib, hmac
enum, dataclasses, abc, contextlib
```

### Blocked Modules

```
socket, ssl, requests, urllib, http (network)
subprocess, os, sys, shutil (system)
ctypes, cffi, mmap (low-level)
pickle, marshal (code injection)
importlib, inspect, gc (introspection)
multiprocessing, threading (concurrency)
```

## JavaScript Sandbox

### Usage

```bash
node lang/javascript/sandbox.js code.js --timeout 5000 --json
```

### Defenses

| Attack | Blocked | Method |
|--------|:-------:|--------|
| `require('net')` | ✅ | Module blocklist |
| `require('child_process')` | ✅ | Module blocklist |
| `require('fs').readFileSync('/etc/passwd')` | ✅ | Restricted fs |
| `process.exit()` | ✅ | No process in context |
| `eval()` | ✅ | Removed from context |
| Infinite loop | ✅ | vm timeout |

### Blocked Modules

```
net, dgram, http, https, http2, tls, dns
child_process, cluster, worker_threads
os, process, v8, inspector
ffi, ffi-napi
```

### Allowed Modules

```
assert, buffer, crypto, events, querystring
string_decoder, url, util, zlib, stream
fs (restricted), path (restricted)
```

---

## LD_PRELOAD Hook (Last Resort)

⚠️ **WARNING: This can be bypassed.** Use only as defense-in-depth.

### Build

```bash
cd lang/preload
make
```

### Usage

```bash
# Block network
LD_PRELOAD=./sandbox_preload.so SANDBOX_NO_NETWORK=1 ./program

# Block fork
LD_PRELOAD=./sandbox_preload.so SANDBOX_NO_FORK=1 ./program

# Restrict filesystem
LD_PRELOAD=./sandbox_preload.so SANDBOX_ALLOW_PATH=/tmp ./program

# All restrictions
LD_PRELOAD=./sandbox_preload.so \
  SANDBOX_NO_NETWORK=1 \
  SANDBOX_NO_FORK=1 \
  SANDBOX_NO_EXEC=1 \
  SANDBOX_ALLOW_PATH=/tmp \
  ./program
```

### Bypass Methods (Known)

| Method | Description |
|--------|-------------|
| Static linking | LD_PRELOAD doesn't affect static binaries |
| Direct syscall | `syscall(SYS_socket, ...)` bypasses libc |
| ctypes/FFI | Call libc functions directly |
| Clear LD_PRELOAD | Partial protection in place |
| setuid binaries | LD_PRELOAD ignored |

### When to Use

- Lambda non-Python as additional layer
- Combined with VPC isolation
- When seccomp not available
- For "speed bump" defense

---

## Integration with Shimmy

```python
# Python
result = subprocess.run(
    ['python3', '/var/task/lang/python/sandbox.py', 
     code_path, '--json', '--timeout', '5'],
    capture_output=True, text=True
)

# JavaScript
result = subprocess.run(
    ['node', '/var/task/lang/javascript/sandbox.js',
     code_path, '--json', '--timeout', '5000'],
    capture_output=True, text=True
)

# Other languages (with LD_PRELOAD)
env = os.environ.copy()
env['LD_PRELOAD'] = '/var/task/lang/preload/sandbox_preload.so'
env['SANDBOX_NO_NETWORK'] = '1'
env['SANDBOX_NO_FORK'] = '1'
env['SANDBOX_ALLOW_PATH'] = '/tmp'
result = subprocess.run(['./program'], env=env, capture_output=True)
```

## Security Notes

1. **Not as strong as seccomp** - Language-level restrictions can potentially be bypassed
2. **Defense in depth** - Combine with VPC isolation and Lambda's built-in protections
3. **Whitelist approach** - Only explicitly allowed modules can be imported
4. **LD_PRELOAD is weak** - Use only as additional layer, never as primary defense
