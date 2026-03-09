import mmap
import os
fd = os.open("/etc/passwd", os.O_RDONLY)
m = mmap.mmap(fd, 0, prot=mmap.PROT_READ)
print(m[:100])
