# Language-Specific Sandboxes

For environments where kernel-level sandboxing (seccomp, Landlock) is unavailable (e.g., AWS Lambda), these language-specific wrappers provide application-level isolation.

## Available Languages

| Language | File | Status |
|----------|------|:------:|
| Python | `python/sandbox.py` | ✅ |
| JavaScript | `javascript/sandbox.js` | 🚧 TODO |
| Java | `java/Sandbox.java` | 🚧 TODO |

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

## Integration with Shimmy

```python
# In shimmy worker
import subprocess
import json

def execute_python(code_path):
    result = subprocess.run(
        ['python3', '/var/task/lang/python/sandbox.py', 
         code_path, '--json', '--timeout', '5'],
        capture_output=True,
        text=True
    )
    return json.loads(result.stdout)
```

## Security Notes

1. **Not as strong as seccomp** - Python-level restrictions can potentially be bypassed through interpreter internals
2. **Defense in depth** - Combine with VPC isolation and Lambda's built-in protections
3. **Whitelist approach** - Only explicitly allowed modules can be imported
