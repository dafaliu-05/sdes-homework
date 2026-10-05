import argparse
from typing import Sequence


P10 = (3, 5, 2, 7, 4, 10, 1, 9, 8, 6)
P8 = (6, 3, 7, 4, 8, 5, 10, 9)
IP = (2, 6, 3, 1, 4, 8, 5, 7)
IP_INV = (4, 1, 3, 5, 7, 2, 8, 6)
EP = (4, 1, 2, 3, 2, 3, 4, 1)
P4 = (2, 4, 3, 1)

S0 = (
    (1, 0, 3, 2),
    (3, 2, 1, 0),
    (0, 2, 1, 3),
    (3, 1, 3, 2),
)
S1 = (
    (0, 1, 2, 3),
    (2, 0, 1, 3),
    (3, 0, 1, 0),
    (2, 1, 0, 3),
)


def _validate_bits(bits: str, length: int, name: str) -> None:
    if not isinstance(bits, str) or len(bits) != length or any(c not in "01" for c in bits):
        raise ValueError(f"{name} must be a {length}-bit binary string")


def _permute(bits: str, table: Sequence[int]) -> str:
    return "".join(bits[position - 1] for position in table)


def _left_shift(bits: str, amount: int) -> str:
    amount %= len(bits)
    return bits[amount:] + bits[:amount]


def _xor(left: str, right: str) -> str:
    if len(left) != len(right):
        raise ValueError("XOR operands must have the same length")
    return "".join("1" if a != b else "0" for a, b in zip(left, right))


def generate_keys(key: str) -> tuple[str, str]:
    _validate_bits(key, 10, "key")

    permuted = _permute(key, P10)
    left, right = permuted[:5], permuted[5:]

    left = _left_shift(left, 1)
    right = _left_shift(right, 1)
    k1 = _permute(left + right, P8)

    left = _left_shift(left, 2)
    right = _left_shift(right, 2)
    k2 = _permute(left + right, P8)
    return k1, k2


def _sbox(bits: str, box: Sequence[Sequence[int]]) -> str:
    # 4 位输入中，第 1、4 位决定行，第 2、3 位决定列。
    row = int(bits[0] + bits[3], 2)
    column = int(bits[1] + bits[2], 2)
    return format(box[row][column], "02b")


def _round(left: str, right: str, subkey: str) -> tuple[str, str]:
    expanded = _permute(right, EP)
    mixed = _xor(expanded, subkey)
    substituted = _sbox(mixed[:4], S0) + _sbox(mixed[4:], S1)
    p4 = _permute(substituted, P4)
    return _xor(left, p4), right


def _fk(block: str, subkey: str) -> str:
    left, right = block[:4], block[4:]
    new_left, unchanged_right = _round(left, right, subkey)
    return new_left + unchanged_right


def encrypt(plaintext: str, key: str) -> str:
    _validate_bits(plaintext, 8, "plaintext")
    k1, k2 = generate_keys(key)

    state = _permute(plaintext, IP)
    state = _fk(state, k1)
    state = state[4:] + state[:4]
    state = _fk(state, k2)
    return _permute(state, IP_INV)


def decrypt(ciphertext: str, key: str) -> str:
    _validate_bits(ciphertext, 8, "ciphertext")
    k1, k2 = generate_keys(key)

    state = _permute(ciphertext, IP)
    state = _fk(state, k2)
    state = state[4:] + state[:4]
    state = _fk(state, k1)
    return _permute(state, IP_INV)


def brute_force(plaintext: str, ciphertext: str) -> list[str]:
    _validate_bits(plaintext, 8, "plaintext")
    _validate_bits(ciphertext, 8, "ciphertext")
    return [
        format(candidate, "010b")
        for candidate in range(1 << 10)
        if encrypt(plaintext, format(candidate, "010b")) == ciphertext
    ]


def exhaustive_round_trip() -> None:
    for key_number in range(1 << 10):
        key = format(key_number, "010b")
        for block_number in range(1 << 8):
            block = format(block_number, "08b")
            if decrypt(encrypt(block, key), key) != block:
                raise AssertionError(f"round-trip failed for key={key}, block={block}")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="S-DES command-line tool")
    subparsers = parser.add_subparsers(dest="command", required=True)

    for command, data_name in (("encrypt", "plaintext"), ("decrypt", "ciphertext")):
        subparser = subparsers.add_parser(command)
        subparser.add_argument("--key", required=True, help="10-bit binary key")
        subparser.add_argument(f"--{data_name}", required=True, help="8-bit binary block")

    keys_parser = subparsers.add_parser("keys")
    keys_parser.add_argument("--key", required=True, help="10-bit binary key")

    crack_parser = subparsers.add_parser("brute-force")
    crack_parser.add_argument("--plaintext", required=True)
    crack_parser.add_argument("--ciphertext", required=True)

    subparsers.add_parser("exhaustive-test")
    return parser


def main() -> None:
    args = _build_parser().parse_args()
    if args.command == "encrypt":
        print(encrypt(args.plaintext, args.key))
    elif args.command == "decrypt":
        print(decrypt(args.ciphertext, args.key))
    elif args.command == "keys":
        k1, k2 = generate_keys(args.key)
        print(f"k1={k1}\nk2={k2}")
    elif args.command == "brute-force":
        print("\n".join(brute_force(args.plaintext, args.ciphertext)) or "no key found")
    elif args.command == "exhaustive-test":
        exhaustive_round_trip()
        print("exhaustive round-trip test passed")


if __name__ == "__main__":
    main()
