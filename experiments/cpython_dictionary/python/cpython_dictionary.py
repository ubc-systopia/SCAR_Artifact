import random

d = {}

for i in range(2**6):
    d[f"i{i}"] = f"item {i}"

key = random.choice(list(d.keys()))


def test():
    return d[key]


def probe(i):
    return d["i" + str(i)]


print("CPython finished initialization")
