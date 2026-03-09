#!/usr/bin/env python3
"""
Sandlock Source Code Scanner

Detects dangerous patterns in source code before compilation/execution.
Use as pre-flight check for untrusted code.

Usage:
    python scanner.py <file> [--json] [--strict]
    python scanner.py --stdin < code.c
"""

import re
import sys
import json
import argparse
from dataclasses import dataclass, field, asdict
from typing import List, Optional
from pathlib import Path

# ============================================================
# Pattern Definitions
# ============================================================

@dataclass
class Pattern:
    name: str
    regex: str
    severity: str  # "critical", "high", "medium", "low"
    description: str
    languages: List[str] = field(default_factory=lambda: ["*"])

# Critical: Direct syscall bypasses
CRITICAL_PATTERNS = [
    Pattern(
        "inline_asm",
        r'\b(asm|__asm__|__asm)\s*(\(|volatile)',
        "critical",
        "Inline assembly can make direct syscalls",
        ["c", "cpp"]
    ),
    Pattern(
        "syscall_instruction_x86",
        r'\bsyscall\b',
        "critical", 
        "x86-64 syscall instruction",
        ["c", "cpp", "asm"]
    ),
    Pattern(
        "int_0x80",
        r'int\s+(0x80|\$0x80|80h)',
        "critical",
        "x86 interrupt for syscall",
        ["c", "cpp", "asm"]
    ),
    Pattern(
        "svc_arm",
        r'svc\s+#?\d+',
        "critical",
        "ARM supervisor call instruction",
        ["c", "cpp", "asm"]
    ),
    Pattern(
        "custom_start",
        r'\b_start\s*\(',
        "critical",
        "Custom entry point bypasses libc",
        ["c", "cpp"]
    ),
    Pattern(
        "libc_start_override",
        r'__libc_start_main',
        "critical",
        "Attempting to override libc startup",
        ["c", "cpp"]
    ),
]

# High: Syscall wrappers and dangerous functions
HIGH_PATTERNS = [
    Pattern(
        "syscall_wrapper",
        r'\bsyscall\s*\(',
        "high",
        "Direct syscall wrapper function",
        ["c", "cpp"]
    ),
    Pattern(
        "sys_constants",
        r'\bSYS_(socket|connect|bind|listen|accept|fork|clone|execve|ptrace|mmap)\b',
        "high",
        "Syscall number constants",
        ["c", "cpp"]
    ),
    Pattern(
        "nr_constants",
        r'__NR_(socket|connect|fork|clone|execve|ptrace)',
        "high",
        "Syscall number macros",
        ["c", "cpp"]
    ),
    Pattern(
        "dlopen",
        r'\bdlopen\s*\(',
        "high",
        "Dynamic library loading",
        ["c", "cpp"]
    ),
    Pattern(
        "dlsym",
        r'\bdlsym\s*\(',
        "high",
        "Dynamic symbol lookup",
        ["c", "cpp"]
    ),
    Pattern(
        "mprotect",
        r'\bmprotect\s*\(',
        "high",
        "Memory protection change (can make code executable)",
        ["c", "cpp"]
    ),
    Pattern(
        "ptrace_call",
        r'\bptrace\s*\(',
        "high",
        "Process tracing",
        ["c", "cpp"]
    ),
    # Python specific
    Pattern(
        "python_ctypes",
        r'\bctypes\b',
        "high",
        "Foreign function interface",
        ["python"]
    ),
    Pattern(
        "python_cffi",
        r'\bcffi\b',
        "high",
        "C Foreign Function Interface",
        ["python"]
    ),
    # JavaScript specific
    Pattern(
        "js_ffi",
        r'\b(ffi|ffi-napi|ref-napi)\b',
        "high",
        "Native addon interface",
        ["javascript"]
    ),
    Pattern(
        "js_native",
        r'process\.binding\s*\(',
        "high",
        "Node.js native binding access",
        ["javascript"]
    ),
    # Rust specific
    Pattern(
        "rust_unsafe",
        r'\bunsafe\s*\{',
        "high",
        "Unsafe block can contain raw syscalls",
        ["rust"]
    ),
    Pattern(
        "rust_asm",
        r'\b(asm!|global_asm!)',
        "critical",
        "Rust inline assembly",
        ["rust"]
    ),
    # Go specific
    Pattern(
        "go_syscall",
        r'syscall\.(Syscall|RawSyscall)',
        "critical",
        "Go direct syscall",
        ["go"]
    ),
    Pattern(
        "go_unsafe",
        r'\bunsafe\.Pointer\b',
        "high",
        "Go unsafe pointer",
        ["go"]
    ),
]

# Medium: Suspicious but sometimes legitimate
MEDIUM_PATTERNS = [
    Pattern(
        "shellcode_bytes",
        r'\\x(48|0f|cd|80|b8|bf|be|ba)',
        "medium",
        "Potential shellcode byte sequences",
        ["c", "cpp", "python"]
    ),
    Pattern(
        "exec_family",
        r'\b(execl|execle|execlp|execv|execve|execvp|execvpe)\s*\(',
        "medium",
        "Exec family functions",
        ["c", "cpp"]
    ),
    Pattern(
        "fork_call",
        r'\b(fork|vfork)\s*\(',
        "medium",
        "Process forking",
        ["c", "cpp"]
    ),
    Pattern(
        "socket_call",
        r'\bsocket\s*\(',
        "medium",
        "Socket creation",
        ["c", "cpp"]
    ),
    Pattern(
        "signal_handler",
        r'\bsignal\s*\(\s*(SIGSEGV|SIGILL|SIGBUS)',
        "medium",
        "Signal handler for crash signals",
        ["c", "cpp"]
    ),
    Pattern(
        "setuid",
        r'\b(setuid|setgid|seteuid|setegid)\s*\(',
        "medium",
        "Privilege modification",
        ["c", "cpp"]
    ),
    # Python
    Pattern(
        "python_os_system",
        r'\bos\.(system|popen|spawn)',
        "medium",
        "Shell command execution",
        ["python"]
    ),
    Pattern(
        "python_subprocess",
        r'\bsubprocess\b',
        "medium",
        "Subprocess module",
        ["python"]
    ),
    Pattern(
        "python_eval",
        r'\b(eval|exec|compile)\s*\(',
        "medium",
        "Dynamic code execution",
        ["python"]
    ),
    # JavaScript
    Pattern(
        "js_child_process",
        r"require\s*\(\s*['\"]child_process['\"]",
        "medium",
        "Child process module",
        ["javascript"]
    ),
    Pattern(
        "js_eval",
        r'\beval\s*\(',
        "medium",
        "Dynamic code execution",
        ["javascript"]
    ),
]

ALL_PATTERNS = CRITICAL_PATTERNS + HIGH_PATTERNS + MEDIUM_PATTERNS

# ============================================================
# Scanner
# ============================================================

@dataclass
class Finding:
    pattern: str
    severity: str
    line: int
    column: int
    match: str
    description: str

@dataclass 
class ScanResult:
    file: str
    language: str
    clean: bool
    findings: List[Finding]
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0

def detect_language(filename: str, content: str) -> str:
    """Detect programming language from filename or content."""
    ext_map = {
        '.c': 'c',
        '.h': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.hpp': 'cpp',
        '.py': 'python',
        '.js': 'javascript',
        '.ts': 'javascript',
        '.rs': 'rust',
        '.go': 'go',
        '.java': 'java',
        '.s': 'asm',
        '.asm': 'asm',
    }
    
    ext = Path(filename).suffix.lower()
    if ext in ext_map:
        return ext_map[ext]
    
    # Heuristic detection (order matters)
    if 'package main' in content or 'func main' in content:
        return 'go'
    if 'fn main' in content or 'fn ' in content:
        return 'rust'
    if '#include' in content or 'int main' in content or 'void ' in content:
        return 'c'
    if 'function ' in content or 'require(' in content or 'const ' in content:
        return 'javascript'
    if 'def ' in content or 'import ' in content:
        return 'python'
    
    return 'unknown'

def scan_code(content: str, filename: str = "<stdin>", strict: bool = False) -> ScanResult:
    """Scan source code for dangerous patterns."""
    language = detect_language(filename, content)
    findings = []
    
    lines = content.split('\n')
    
    for pattern in ALL_PATTERNS:
        # Check if pattern applies to this language
        # Critical patterns also check unknown languages for safety
        if "*" not in pattern.languages and language not in pattern.languages:
            if not (pattern.severity == "critical" and language == "unknown"):
                continue
            
        # Skip medium patterns in non-strict mode
        if not strict and pattern.severity == "medium":
            continue
        
        regex = re.compile(pattern.regex, re.IGNORECASE)
        
        for line_num, line in enumerate(lines, 1):
            # Skip comments (basic heuristic)
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('#') or stripped.startswith('*'):
                continue
                
            for match in regex.finditer(line):
                findings.append(Finding(
                    pattern=pattern.name,
                    severity=pattern.severity,
                    line=line_num,
                    column=match.start() + 1,
                    match=match.group()[:50],  # Truncate long matches
                    description=pattern.description,
                ))
    
    # Count by severity
    critical = sum(1 for f in findings if f.severity == "critical")
    high = sum(1 for f in findings if f.severity == "high")
    medium = sum(1 for f in findings if f.severity == "medium")
    
    return ScanResult(
        file=filename,
        language=language,
        clean=(critical == 0 and high == 0),
        findings=findings,
        critical_count=critical,
        high_count=high,
        medium_count=medium,
    )

# ============================================================
# CLI
# ============================================================

def format_text(result: ScanResult) -> str:
    """Format scan result as human-readable text."""
    lines = []
    
    if result.clean:
        lines.append(f"✓ {result.file} ({result.language}): CLEAN")
        if result.medium_count > 0:
            lines.append(f"  (Note: {result.medium_count} medium findings ignored, use --strict)")
        return '\n'.join(lines)
    
    lines.append(f"✗ {result.file} ({result.language}): {result.critical_count} critical, {result.high_count} high")
    lines.append("")
    
    for f in sorted(result.findings, key=lambda x: (x.severity != "critical", x.severity != "high", x.line)):
        severity_icon = {"critical": "🔴", "high": "🟠", "medium": "🟡"}[f.severity]
        lines.append(f"  {severity_icon} Line {f.line}: [{f.pattern}] {f.match}")
        lines.append(f"     {f.description}")
    
    return '\n'.join(lines)

def main():
    parser = argparse.ArgumentParser(description="Sandlock Source Code Scanner")
    parser.add_argument("file", nargs="?", help="File to scan")
    parser.add_argument("--stdin", action="store_true", help="Read from stdin")
    parser.add_argument("--json", action="store_true", help="Output as JSON")
    parser.add_argument("--strict", action="store_true", help="Include medium severity findings")
    parser.add_argument("--language", help="Force language detection")
    args = parser.parse_args()
    
    if args.stdin:
        content = sys.stdin.read()
        filename = "<stdin>"
    elif args.file:
        try:
            content = Path(args.file).read_text()
            filename = args.file
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
    else:
        parser.print_help()
        sys.exit(1)
    
    result = scan_code(content, filename, strict=args.strict)
    
    if args.json:
        output = {
            "file": result.file,
            "language": result.language,
            "clean": result.clean,
            "critical": result.critical_count,
            "high": result.high_count,
            "medium": result.medium_count,
            "findings": [asdict(f) for f in result.findings],
        }
        print(json.dumps(output, indent=2))
    else:
        print(format_text(result))
    
    # Exit code: 0 if clean, 1 if critical/high found
    sys.exit(0 if result.clean else 1)

if __name__ == "__main__":
    main()
