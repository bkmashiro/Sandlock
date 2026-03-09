#!/usr/bin/env python3
"""
Sandlock Python Sandbox
Language-level restrictions for Lambda environments where seccomp is unavailable.

Usage:
    python3 sandbox.py <code_file> [--timeout N] [--memory MB] [--workdir DIR]
"""

import sys
import os
import builtins
import resource
import signal
import argparse
import traceback
from io import StringIO

# ============================================================
# Configuration
# ============================================================

BLOCKED_MODULES = {
    # Network
    'socket', 'ssl', 'requests', 'urllib', 'urllib3', 'http', 'httplib',
    'ftplib', 'smtplib', 'poplib', 'imaplib', 'telnetlib', 'asyncio',
    
    # Process/System
    'subprocess', 'os', 'sys', 'shutil', 'pathlib',
    'multiprocessing', 'threading', 'concurrent', '_thread',
    'signal', 'resource', 'pty', 'tty', 'termios', 'fcntl',
    
    # Low-level
    'ctypes', 'cffi', '_ctypes', 'ffi',
    'mmap', 'sysconfig', 'platform',
    
    # Serialization (code injection risk)
    'pickle', 'cPickle', 'marshal', 'shelve',
    
    # Import manipulation
    'importlib', 'imp', 'pkgutil', 'zipimport',
    
    # Introspection
    'inspect', 'gc', 'traceback', 'dis', 'code', 'codeop',
    
    # File operations
    'tempfile', 'glob', 'fnmatch',
    
    # Other dangerous
    'atexit', 'sched', 'select', 'selectors',
    'pwd', 'grp', 'crypt', 'spwd',
}

SAFE_BUILTINS = {
    # Types
    'int', 'float', 'str', 'bool', 'bytes', 'bytearray',
    'list', 'dict', 'set', 'frozenset', 'tuple',
    'complex', 'slice', 'range', 'type', 'object',
    
    # Functions
    'print', 'input', 'len', 'abs', 'round', 'pow',
    'min', 'max', 'sum', 'sorted', 'reversed',
    'enumerate', 'zip', 'map', 'filter', 'all', 'any',
    'iter', 'next', 'hash', 'id', 'repr', 'ascii',
    'bin', 'oct', 'hex', 'ord', 'chr',
    'format', 'divmod', 'isinstance', 'issubclass',
    'callable', 'hasattr', 'getattr', 'setattr', 'delattr',
    
    # Constants
    'True', 'False', 'None', 'Ellipsis', 'NotImplemented',
    
    # Exceptions (read-only)
    'Exception', 'BaseException', 'StopIteration', 'GeneratorExit',
    'ArithmeticError', 'AssertionError', 'AttributeError',
    'EOFError', 'IndexError', 'KeyError', 'KeyboardInterrupt',
    'MemoryError', 'NameError', 'OverflowError', 'RuntimeError',
    'RecursionError', 'SyntaxError', 'IndentationError', 'TabError',
    'SystemError', 'TypeError', 'UnboundLocalError', 'UnicodeError',
    'ValueError', 'ZeroDivisionError', 'LookupError', 'ImportError',
    'ModuleNotFoundError', 'OSError', 'IOError', 'FileNotFoundError',
    'PermissionError', 'FileExistsError', 'IsADirectoryError',
    'NotADirectoryError', 'TimeoutError', 'ConnectionError',
    'Warning', 'UserWarning', 'DeprecationWarning', 'RuntimeWarning',
}

ALLOWED_MODULES = {
    # Math
    'math', 'cmath', 'decimal', 'fractions', 'random', 'statistics',
    
    # Data
    'json', 'csv', 're', 'string', 'textwrap',
    'collections', 'heapq', 'bisect', 'array',
    'itertools', 'functools', 'operator',
    
    # Date/Time
    'datetime', 'time', 'calendar',
    
    # Types
    'typing', 'types', 'copy', 'pprint',
    
    # Encoding
    'base64', 'binascii', 'codecs', 'unicodedata',
    'hashlib', 'hmac',
    
    # Other safe
    'enum', 'dataclasses', 'abc', 'contextlib',
    'numbers', 'io',
}

# ============================================================
# Import Hook
# ============================================================

class SandboxImporter:
    """Blocks dangerous module imports"""
    
    def find_module(self, fullname, path=None):
        # Get root module name
        root = fullname.split('.')[0]
        
        # Block if in blacklist
        if root in BLOCKED_MODULES:
            return self
        
        # Allow if in whitelist
        if root in ALLOWED_MODULES:
            return None
        
        # Block unknown modules by default (strict mode)
        return self
    
    def load_module(self, fullname):
        raise ImportError(f"Module '{fullname}' is not allowed in sandbox")


# ============================================================
# Restricted Builtins
# ============================================================

class RestrictedOpen:
    """Restricts file access to /tmp only"""
    
    def __init__(self, workdir='/tmp'):
        self.workdir = os.path.abspath(workdir)
        self._original = builtins.open
    
    def __call__(self, path, mode='r', *args, **kwargs):
        # Resolve absolute path
        if not os.path.isabs(path):
            path = os.path.join(self.workdir, path)
        path = os.path.abspath(path)
        
        # Check if path is within allowed directory
        if not path.startswith(self.workdir):
            raise PermissionError(f"Access denied: {path} (only {self.workdir} allowed)")
        
        # Block write to anything outside /tmp
        if 'w' in mode or 'a' in mode or '+' in mode:
            if not path.startswith('/tmp'):
                raise PermissionError(f"Write access denied: {path}")
        
        return self._original(path, mode, *args, **kwargs)


class RestrictedImport:
    """Only allows importing whitelisted modules"""
    
    def __init__(self):
        self._original = builtins.__import__
    
    def __call__(self, name, globals=None, locals=None, fromlist=(), level=0):
        root = name.split('.')[0]
        
        if root in BLOCKED_MODULES:
            raise ImportError(f"Module '{name}' is blocked")
        
        if root not in ALLOWED_MODULES:
            raise ImportError(f"Module '{name}' is not in whitelist")
        
        return self._original(name, globals, locals, fromlist, level)


def make_restricted_builtins(workdir='/tmp'):
    """Create a restricted builtins dict"""
    restricted = {}
    
    for name in SAFE_BUILTINS:
        if hasattr(builtins, name):
            restricted[name] = getattr(builtins, name)
    
    # Add restricted open
    restricted['open'] = RestrictedOpen(workdir)
    
    # Add restricted import
    restricted['__import__'] = RestrictedImport()
    
    # Remove dangerous builtins explicitly
    for dangerous in ['eval', 'exec', 'compile',
                      'globals', 'locals', 'vars', 'dir',
                      'memoryview', 'breakpoint']:
        restricted.pop(dangerous, None)
    
    return restricted


# ============================================================
# Resource Limits
# ============================================================

def set_resource_limits(cpu_seconds=5, memory_mb=256, fsize_mb=10):
    """Set resource limits using rlimit"""
    
    # CPU time
    if cpu_seconds > 0:
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
    
    # Virtual memory
    if memory_mb > 0:
        mem_bytes = memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    
    # File size
    if fsize_mb > 0:
        fsize_bytes = fsize_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_FSIZE, (fsize_bytes, fsize_bytes))
    
    # No core dumps
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    
    # Stack size (8MB)
    resource.setrlimit(resource.RLIMIT_STACK, (8*1024*1024, 8*1024*1024))


# ============================================================
# Sandbox Execution
# ============================================================

class TimeoutError(Exception):
    pass

def timeout_handler(signum, frame):
    raise TimeoutError("Execution timed out")

def run_sandboxed(code, workdir='/tmp', timeout=5, memory_mb=256):
    """
    Execute code in sandbox with restrictions.
    
    Returns: (success, output, error)
    """
    # Install import hook
    sys.meta_path.insert(0, SandboxImporter())
    
    # Set up restricted builtins
    restricted_builtins = make_restricted_builtins(workdir)
    
    # Create execution namespace
    namespace = {
        '__builtins__': restricted_builtins,
        '__name__': '__main__',
        '__doc__': None,
    }
    
    # Set resource limits
    set_resource_limits(cpu_seconds=timeout, memory_mb=memory_mb)
    
    # Set timeout signal
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout + 1)  # Extra second for cleanup
    
    # Capture output
    old_stdout = sys.stdout
    old_stderr = sys.stderr
    sys.stdout = StringIO()
    sys.stderr = StringIO()
    
    success = True
    error = None
    
    try:
        # Change to workdir
        os.chdir(workdir)
        
        # Compile and execute
        compiled = compile(code, '<sandbox>', 'exec')
        exec(compiled, namespace)
        
    except TimeoutError as e:
        success = False
        error = str(e)
    except MemoryError:
        success = False
        error = "Memory limit exceeded"
    except ImportError as e:
        success = False
        error = f"Import blocked: {e}"
    except PermissionError as e:
        success = False
        error = f"Permission denied: {e}"
    except Exception as e:
        success = False
        error = f"{type(e).__name__}: {e}"
    finally:
        signal.alarm(0)
        output = sys.stdout.getvalue()
        err_output = sys.stderr.getvalue()
        sys.stdout = old_stdout
        sys.stderr = old_stderr
    
    if err_output and not error:
        error = err_output
    
    return success, output, error


# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description='Sandlock Python Sandbox')
    parser.add_argument('code_file', help='Python file to execute')
    parser.add_argument('--timeout', type=int, default=5, help='Timeout in seconds')
    parser.add_argument('--memory', type=int, default=256, help='Memory limit in MB')
    parser.add_argument('--workdir', default='/tmp', help='Working directory')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    
    args = parser.parse_args()
    
    # Read code
    with open(args.code_file, 'r') as f:
        code = f.read()
    
    # Execute
    success, output, error = run_sandboxed(
        code,
        workdir=args.workdir,
        timeout=args.timeout,
        memory_mb=args.memory
    )
    
    # Output
    if args.json:
        import json
        print(json.dumps({
            'success': success,
            'output': output,
            'error': error
        }))
    else:
        if output:
            print(output, end='')
        if error:
            print(f"Error: {error}", file=sys.stderr)
        sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
