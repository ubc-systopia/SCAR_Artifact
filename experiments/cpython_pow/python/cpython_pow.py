import rsa


def set_key(path):
    global key
    print("load rsa key", path)
    with open(path) as kf:
        kd = kf.read()
    key = rsa.PrivateKey.load_pkcs1(kd)
    with open("private.key", "w+") as kf:
        kf.write(bin(key.d) + "\n")


set_key(globals().get("key_path", "private.pem"))


def test():
    global key
    return rsa.sign(b"Hello, world!", key, "SHA-256")


print("Python script initialized")
