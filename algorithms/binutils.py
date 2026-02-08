import hashlib


def index_height(i) -> int:
    pos = i + 1
    while not all_ones(pos):
        pos = pos - most_sig_bit(pos) + 1

    return bit_length(pos) - 1


def hash_pospair64(pos, a, b):

    # Note: Hash algorithm agility is tbd, this example uses SHA-256
    h = hashlib.sha256()

    # Take the big endian representation of pos
    h.update(pos.to_bytes(8, byteorder="big", signed=False))
    h.update(a)
    h.update(b)
    return h.digest()


def all_ones(pos) -> bool:
    msb = most_sig_bit(pos)
    mask = (1 << (msb + 1)) - 1
    return pos == mask


def most_sig_bit(pos) -> int:
    return 1 << (pos.bit_length() - 1)


def bit_length(pos):
    return pos.bit_length()


def log2floor(x):
    """Returns the floor of log base 2 (x)"""
    return x.bit_length() - 1
