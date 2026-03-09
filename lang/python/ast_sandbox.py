#!/usr/bin/env python3
"""
Sandlock Python AST Sandbox (Experimental)

Transforms Python AST to block dangerous operations at compile time.
Faster than import hooks (~2.5ms vs ~13ms).

Usage:
    python ast_sandbox.py <code_file> [--timeout N] [--json]
    python ast_sandbox.py --eval "print(1+1)"
"""

import ast
import sys
import json
import argparse
import builtins
import resource
import signal
from typing import Set, Dict, Any, Optional
from pathlib import Path

# ============================================================
# Configuration
# ============================================================

# Blocked function names
BLOCKED_FUNCTIONS: Set[str] = {
    # Process
    'exec', 'eval', 'compile', 'execfile',
    '__import__', 'reload',
    
    # System
    'exit', 'quit', 'input', 'raw_input',
    'breakpoint', 'help',
    
    # File (handled separately with path check)
    # 'open',
}

# Blocked module attributes
BLOCKED_ATTRS: Dict[str, Set[str]] = {
    'os': {'system', 'popen', 'spawn', 'fork', 'exec', 'execl', 'execle', 
           'execlp', 'execv', 'execve', 'execvp', 'execvpe', 'kill',
           'remove', 'unlink', 'rmdir', 'rename', 'chmod', 'chown',
           'symlink', 'link', 'mknod', 'mkfifo'},
    'subprocess': {'*'},  # Block entire module
    'socket': {'*'},
    'ctypes': {'*'},
    'multiprocessing': {'*'},
    'threading': {'Thread', 'start_new_thread'},
    'sys': {'exit', '_getframe', 'settrace', 'setprofile'},
    'builtins': BLOCKED_FUNCTIONS,
}

# Blocked imports
BLOCKED_IMPORTS: Set[str] = {
    'socket', 'ssl', 'requests', 'urllib', 'http', 'ftplib', 'smtplib',
    'subprocess', 'multiprocessing', 'threading',
    'ctypes', 'cffi', '_ctypes',
    'os', 'sys', 'shutil', 'glob', 'tempfile',
    'pickle', 'marshal', 'shelve',
    'code', 'codeop', 'compileall',
    'gc', 'inspect', 'traceback',
    'importlib', 'pkgutil', 'modulefinder',
    'pty', 'tty', 'termios',
    'signal', 'resource', 'rlimit',
    'mmap', 'fcntl', 'select', 'selectors',
}

# Allowed modules (whitelist mode)
ALLOWED_IMPORTS: Set[str] = {
    'math', 'cmath', 'decimal', 'fractions', 'random', 'statistics',
    'json', 'csv', 're', 'string',
    'collections', 'heapq', 'bisect', 'array',
    'itertools', 'functools', 'operator',
    'datetime', 'time', 'calendar',
    'typing', 'types', 'copy', 'pprint',
    'base64', 'binascii', 'hashlib', 'hmac',
    'enum', 'dataclasses', 'abc', 'contextlib',
}

# ============================================================
# AST Transformers
# ============================================================

class SecurityError(Exception):
    """Raised when blocked operation is detected."""
    pass

class DangerousCodeDetector(ast.NodeVisitor):
    """First pass: detect dangerous patterns without transformation."""
    
    def __init__(self):
        self.violations = []
    
    def visit_Import(self, node: ast.Import):
        for alias in node.names:
            module = alias.name.split('.')[0]
            if module in BLOCKED_IMPORTS:
                self.violations.append(
                    f"Line {node.lineno}: Blocked import '{module}'"
                )
        self.generic_visit(node)
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        if node.module:
            module = node.module.split('.')[0]
            if module in BLOCKED_IMPORTS:
                self.violations.append(
                    f"Line {node.lineno}: Blocked import from '{module}'"
                )
        self.generic_visit(node)
    
    def visit_Call(self, node: ast.Call):
        # Check direct function calls
        if isinstance(node.func, ast.Name):
            if node.func.id in BLOCKED_FUNCTIONS:
                self.violations.append(
                    f"Line {node.lineno}: Blocked function '{node.func.id}'"
                )
        
        # Check attribute calls (e.g., os.system)
        elif isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                module = node.func.value.id
                attr = node.func.attr
                if module in BLOCKED_ATTRS:
                    blocked = BLOCKED_ATTRS[module]
                    if '*' in blocked or attr in blocked:
                        self.violations.append(
                            f"Line {node.lineno}: Blocked call '{module}.{attr}'"
                        )
        
        self.generic_visit(node)

class CodeTransformer(ast.NodeTransformer):
    """Second pass: transform AST to inject security checks."""
    
    def __init__(self):
        self.injected_helpers = False
    
    def visit_Module(self, node: ast.Module):
        """Inject helper functions at module start."""
        self.generic_visit(node)
        
        # Add security helpers at the beginning
        helpers = ast.parse('''
def _sandlock_blocked(name):
    raise SecurityError(f"Blocked: {name}")

def _sandlock_check_open(path, mode='r', *args, **kwargs):
    # Simple path check without os.path
    path_str = str(path)
    if path_str.startswith('/tmp') or path_str.startswith('./') or not path_str.startswith('/'):
        return _original_open(path, mode, *args, **kwargs)
    raise SecurityError(f"File access denied: {path}")

_original_open = open
''').body
        
        node.body = helpers + node.body
        return node
    
    def visit_Call(self, node: ast.Call):
        """Transform dangerous calls to security checks."""
        self.generic_visit(node)
        
        # Transform open() to _sandlock_check_open()
        if isinstance(node.func, ast.Name) and node.func.id == 'open':
            node.func.id = '_sandlock_check_open'
        
        # Transform blocked functions to raise error
        elif isinstance(node.func, ast.Name) and node.func.id in BLOCKED_FUNCTIONS:
            return ast.Call(
                func=ast.Name(id='_sandlock_blocked', ctx=ast.Load()),
                args=[ast.Constant(value=node.func.id)],
                keywords=[]
            )
        
        return node
    
    def visit_Import(self, node: ast.Import):
        """Block dangerous imports."""
        safe_aliases = []
        for alias in node.names:
            module = alias.name.split('.')[0]
            if module not in BLOCKED_IMPORTS:
                safe_aliases.append(alias)
        
        if not safe_aliases:
            # Replace with pass
            return ast.Pass()
        
        node.names = safe_aliases
        return node
    
    def visit_ImportFrom(self, node: ast.ImportFrom):
        """Block dangerous import-from statements."""
        if node.module:
            module = node.module.split('.')[0]
            if module in BLOCKED_IMPORTS:
                return ast.Pass()
        return node

# ============================================================
# Sandbox Execution
# ============================================================

def create_safe_globals() -> Dict[str, Any]:
    """Create restricted global namespace."""
    safe_builtins = {}
    
    # Copy safe builtins
    for name in dir(builtins):
        if not name.startswith('_') and name not in BLOCKED_FUNCTIONS:
            safe_builtins[name] = getattr(builtins, name)
    
    # Add security exception
    safe_builtins['SecurityError'] = SecurityError
    
    return {
        '__builtins__': safe_builtins,
        '__name__': '__main__',
        '__doc__': None,
    }

def set_limits(timeout: int = 5, memory_mb: int = 128):
    """Set resource limits (best effort)."""
    try:
        # CPU time
        resource.setrlimit(resource.RLIMIT_CPU, (timeout, timeout))
    except (ValueError, resource.error):
        pass  # Cannot set on some systems
    
    try:
        # Memory
        mem_bytes = memory_mb * 1024 * 1024
        resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
    except (ValueError, resource.error):
        pass
    
    try:
        # File size
        resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
    except (ValueError, resource.error):
        pass
    
    # Timeout signal (always works)
    def timeout_handler(signum, frame):
        raise TimeoutError("Execution timed out")
    
    signal.signal(signal.SIGALRM, timeout_handler)
    signal.alarm(timeout)

def run_sandboxed(code: str, timeout: int = 5, memory_mb: int = 128) -> Dict[str, Any]:
    """Execute code in AST sandbox."""
    result = {
        'success': True,
        'output': '',
        'error': None,
        'violations': [],
    }
    
    try:
        # Parse AST
        tree = ast.parse(code)
        
        # First pass: detect violations
        detector = DangerousCodeDetector()
        detector.visit(tree)
        
        if detector.violations:
            result['success'] = False
            result['violations'] = detector.violations
            result['error'] = f"Security violations detected: {len(detector.violations)}"
            return result
        
        # Second pass: transform AST
        transformer = CodeTransformer()
        tree = transformer.visit(tree)
        ast.fix_missing_locations(tree)
        
        # Compile
        compiled = compile(tree, '<sandbox>', 'exec')
        
        # Set limits
        set_limits(timeout, memory_mb)
        
        # Capture output
        import io
        from contextlib import redirect_stdout, redirect_stderr
        
        stdout_capture = io.StringIO()
        stderr_capture = io.StringIO()
        
        # Execute
        globals_dict = create_safe_globals()
        
        with redirect_stdout(stdout_capture), redirect_stderr(stderr_capture):
            exec(compiled, globals_dict)
        
        result['output'] = stdout_capture.getvalue()
        if stderr_capture.getvalue():
            result['output'] += '\n[stderr]\n' + stderr_capture.getvalue()
        
    except SecurityError as e:
        result['success'] = False
        result['error'] = f"Security violation: {e}"
    except TimeoutError as e:
        result['success'] = False
        result['error'] = str(e)
    except MemoryError:
        result['success'] = False
        result['error'] = "Memory limit exceeded"
    except SyntaxError as e:
        result['success'] = False
        result['error'] = f"Syntax error: {e}"
    except Exception as e:
        result['success'] = False
        result['error'] = f"{type(e).__name__}: {e}"
    finally:
        signal.alarm(0)
    
    return result

# ============================================================
# CLI
# ============================================================

def main():
    parser = argparse.ArgumentParser(description="Sandlock AST Sandbox (Experimental)")
    parser.add_argument('file', nargs='?', help='Python file to execute')
    parser.add_argument('--eval', '-e', help='Code string to evaluate')
    parser.add_argument('--timeout', '-t', type=int, default=5, help='Timeout in seconds')
    parser.add_argument('--memory', '-m', type=int, default=128, help='Memory limit in MB')
    parser.add_argument('--json', action='store_true', help='Output as JSON')
    parser.add_argument('--check', action='store_true', help='Only check, do not execute')
    args = parser.parse_args()
    
    # Get code
    if args.eval:
        code = args.eval
    elif args.file:
        code = Path(args.file).read_text()
    else:
        parser.print_help()
        sys.exit(1)
    
    if args.check:
        # Only detect violations
        tree = ast.parse(code)
        detector = DangerousCodeDetector()
        detector.visit(tree)
        
        if args.json:
            print(json.dumps({
                'clean': len(detector.violations) == 0,
                'violations': detector.violations
            }))
        else:
            if detector.violations:
                for v in detector.violations:
                    print(f"❌ {v}")
                sys.exit(1)
            else:
                print("✓ No violations detected")
        sys.exit(0)
    
    # Execute
    result = run_sandboxed(code, args.timeout, args.memory)
    
    if args.json:
        print(json.dumps(result))
    else:
        if result['output']:
            print(result['output'], end='')
        if result['error']:
            print(f"Error: {result['error']}", file=sys.stderr)
        if result['violations']:
            for v in result['violations']:
                print(f"⚠ {v}", file=sys.stderr)
    
    sys.exit(0 if result['success'] else 1)

if __name__ == '__main__':
    main()
