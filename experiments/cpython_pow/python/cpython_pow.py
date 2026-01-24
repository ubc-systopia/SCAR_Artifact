import rsa

with open("private.pem") as kf:
    kd = kf.read()

key = rsa.PrivateKey.load_pkcs1(kd)

with open("private.key", "w+") as kf:
    kf.write(bin(key.d) + "\n")


def test():
    return rsa.sign(b"Hello, world!", key, "SHA-256")


print("Python script initialized")