import ctypes
libc = ctypes.CDLL(None)
# Try to call fork via syscall
libc.syscall(57)  # __NR_fork on x86_64
