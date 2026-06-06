#!/usr/bin/env python3

import os
import subprocess
import sys
from argparse import ArgumentParser


def gen_key(path, bits):
    subprocess.run(
        ["openssl", "genrsa", "-out", path, "-traditional", str(bits)],
        check=True,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def main():
    parser = ArgumentParser(
        prog="gen_key_pool",
        description="Generate a pool of RSA private keys for the cpython_pow case study",
    )
    parser.add_argument(
        "--count", type=int, default=128, help="Number of keys to generate (default: 128)"
    )
    parser.add_argument(
        "--bits", type=int, default=4096, help="RSA modulus size in bits (default: 4096)"
    )
    parser.add_argument(
        "--output",
        type=str,
        default=os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "rsa_key_pool"
        ),
        help="Output directory for the key pool",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="Overwrite existing keys instead of skipping them",
    )
    args = parser.parse_args()

    os.makedirs(args.output, exist_ok=True)
    print(f"Generating {args.count} x {args.bits}-bit RSA keys into {args.output}")

    for i in range(args.count):
        path = os.path.join(args.output, f"rsa_key_{i}.pem")
        if os.path.exists(path) and not args.force:
            print(f"[{i + 1}/{args.count}] skip existing {path}")
            continue
        print(f"[{i + 1}/{args.count}] generating {path}")
        gen_key(path, args.bits)

    print("Done")


if __name__ == "__main__":
    sys.exit(main())
