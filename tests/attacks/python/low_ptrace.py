import ctypes
libc = ctypes.CDLL(None)
libc.ptrace(0, 0, 0, 0)
