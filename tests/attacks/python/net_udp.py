import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.sendto(b"test", ("8.8.8.8", 53))
print("UDP sent")
