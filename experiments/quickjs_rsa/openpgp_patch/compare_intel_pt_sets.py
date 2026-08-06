#!/usr/bin/env python3
"""Set-difference decoded Intel PT instructions and their cache lines."""

import argparse
import re


CACHE_LINE_SIZE = 64
TARGETS = (
    "case_OP_add",
    "js_add_slow",
    "js_binary_arith_bigint",
    "bf_add",
    "__bf_add",
    "bf_add_internal",
    "bf_resize",
    "bf_normalize_and_round",
)

INSTRUCTION_RE = re.compile(
    r"^\s*([0-9a-fA-F]+)\s+(\S+?)(?:\+0x([0-9a-fA-F]+))?\s+"
    r"\([^)]*\)\s+insn:\s+(.+?)\s*$"
)


def load(path):
    instructions = {}
    with open(path, errors="replace") as source:
        for raw_line in source:
            if not any(target in raw_line for target in TARGETS):
                continue
            match = INSTRUCTION_RE.match(raw_line)
            if not match:
                continue
            address = int(match.group(1), 16)
            symbol = match.group(2)
            offset = int(match.group(3) or "0", 16)
            instructions[address] = (symbol, offset, match.group(4))
    return instructions


def cache_line(address):
    return address & ~(CACHE_LINE_SIZE - 1)


def format_instruction(address, details):
    symbol, offset, encoding = details
    return (
        f"0x{address:012x}  line=0x{cache_line(address):012x}  "
        f"{symbol}+0x{offset:x}  insn: {encoding}"
    )


def emit_side(name, addresses, instructions, other_lines):
    lines = {cache_line(address) for address in addresses}
    exclusive_lines = lines - other_lines
    print(f"\n{name}-only instructions ({len(addresses)}):")
    for address in sorted(addresses):
        print(format_instruction(address, instructions[address]))
    print(f"\n{name}-only cache lines ({len(exclusive_lines)}):")
    for line in sorted(exclusive_lines):
        print(f"0x{line:012x}")


def main():
    parser = argparse.ArgumentParser(
        description="Set-difference focused decoded Intel PT instructions"
    )
    parser.add_argument("false_trace")
    parser.add_argument("true_trace")
    args = parser.parse_args()

    false = load(args.false_trace)
    true = load(args.true_trace)
    if not false or not true:
        raise SystemExit("no focused instructions found in one or both traces")

    false_addresses = set(false)
    true_addresses = set(true)
    false_lines = {cache_line(address) for address in false_addresses}
    true_lines = {cache_line(address) for address in true_addresses}

    print(f"cache line size: {CACHE_LINE_SIZE} bytes")
    print(f"false unique instructions: {len(false_addresses)}")
    print(f"true unique instructions:  {len(true_addresses)}")
    print(f"false unique cache lines:  {len(false_lines)}")
    print(f"true unique cache lines:   {len(true_lines)}")
    emit_side("false", false_addresses - true_addresses, false, true_lines)
    emit_side("true", true_addresses - false_addresses, true, false_lines)


if __name__ == "__main__":
    main()
