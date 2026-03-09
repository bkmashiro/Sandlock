with open("/tmp/bigfile", "w") as f:
    for i in range(10000000):
        f.write("x" * 1000)
