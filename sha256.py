# -*- coding: utf-8 -*-

from binascii import unhexlify
"""
Symbols and Operations
    The following symbols are used in the secure hash algorithm specifications; each operates on w-bit words:
    ∧ Bitwise AND operation.
    ∨ Bitwise OR (“inclusive-OR”) operation.
    ⊕ Bitwise XOR (“exclusive-OR”) operation.
    ¬ Bitwise complement operation.
    + Addition modulo 2w.
    << Left-shift operation, where x << n is obtained by discarding the left-most n bits of the word x
        and then padding the result with n zeroes on the right.
    >> Right-shift operation, where x >> n is obtained by discarding the rightmost n bits of the word x
        and then padding the result with n zeroes on the left.
"""


BLOCK_SIZE = 64
DIGEST_SIZE = 32
BITS_IN_WORD = 32  # w - Number of bits in a word.

# SHA-224 and SHA-256 use the same sequence of sixty-four constant 32-bit words.These words represent
# the first thirty-two bits of the fractional parts of the cube roots of the first sixty-four prime numbers.
K256 = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
]

# Before hash computation begins for each of the secure hash algorithms, the initial hash value,
# H(0), must be set. The size and number of words in H(0) depends on the message digest size.
# For SHA-256, the initial hash value, H(0), shall consist of the following eight 32-bit words, in hex:
INITIAL_HASH = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]


def shift_right(x, n):
    """The right shift operation SHR n(x), where x is a w-bit word and n is an integer with 0 ≤ n < w, is defined by
    SHR n (x)=x >> n.
    """
    return (x & 0xffffffff) >> n


def rotate_right(x, y):
    """The rotate right (circular right shift) operation, where x is a w-bit word
    and n is an integer with 0 ≤ n < w, is defined by ROTR n (x) =(x >> n) ∨ (x << w - n).
    """
    return (((x & 0xffffffff) >> (y & 31)) | (x << (BITS_IN_WORD - (y & 31)))) & 0xffffffff


"""
SHA256 uses six logical functions, where each function operates on 64-bit words,
which are represented as x, y, and z. The result of each function is a new 64-bit word.
"""


def choose(x, y, z):
    """The x input chooses if the output is from y or z.
    Ch(x,y,z)=(x∧y)⊕(¬x∧z)
    """
    return z ^ (x & (y ^ z))


def majority(x, y, z):
    """The result is set according to the majority of the 3 inputs.
    Maj(x, y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ ( y ∧ z)
    The functions are defined for bit vectors (of 32 bits in case fo SHA-256)
    """
    return ((x | y) & z) | (x & y)


def sigma0(x):
    # ROTR 2(x) ⊕ ROTR 13(x) ⊕ ROTR 22(x)
    return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22)


def sigma1(x):
    # ROTR 6(x) ⊕ ROTR 11(x) ⊕ ROTR 25(x)
    return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25)


def gamma0(x):
    # ROTR 7(x) ⊕ ROTR 18(x) ⊕ SHR 3(x)
    return rotate_right(x, 7) ^ rotate_right(x, 18) ^ shift_right(x, 3)


def gamma1(x):
    # ROTR 17(x) ⊕ ROTR 19(x) ⊕ SHR 10(x)
    return rotate_right(x, 17) ^ rotate_right(x, 19) ^ shift_right(x, 10)


def mutate(data, digest):
    digest_copy = digest[:]

    # 6.2.2:  The SHA-256 hash computation uses functions and constants previously
    # defined in Sec. 4.1.2 and Sec. 4.2.2, respectively.
    # Addition (+) is performed modulo 232.

    # Prepare the message schedule, {Wt}:
    w = []
    for i in range(0, 16):
        w.append(sum([
            data[4 * i + 0] << 24,
            data[4 * i + 1] << 16,
            data[4 * i + 2] << 8,
            data[4 * i + 3] << 0,
        ]))

    for i in range(16, 64):
        sum_ = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16]
        w.append(sum_ & 0xffffffff)

    for idx in range(0, -64, -1):
        i = abs(idx % 8)

        # Initialize the eight working variables, a, b, c, d, e, f, g, and h  with the (i-1)st hash value.
        # W is the prepared message schedule.
        positions = [(i + x) % 8 for x in range(8)]
        d_position = positions[3]
        h_position = positions[-1]
        a, b, c, d, e, f, g, h = [digest_copy[pos] for pos in positions]

        t1 = h + sigma1(e) + choose(e, f, g) + K256[abs(idx)] + w[abs(idx)]
        t2 = sigma0(a) + majority(a, b, c)
        digest_copy[d_position] = (d + t1) & 0xffffffff
        digest_copy[h_position] = (t1 + t2) & 0xffffffff

    return [(x + digest_copy[idx]) & 0xffffffff
            for idx, x in enumerate(digest)]


def digest_to_hex(digest):
    # tansforms a list of integers into one hex string
    # example
    # [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19] into
    # 6A09E667BB67AE853C6EF372A54FF53A510E527F9B05688C1F83D9AB5BE0CD19
    out = ''
    for i in digest:
        r = hex(i)[2:]
        l = len(r)
        if l < 8:
            # append zeroes to make the string always of length 8
            r = ('0' * (8 - l)) + r
        out += r
    return out


def get_extra_empty_block(length, add_one_at_the_start=False):
    # returns an empty block with all zeroes except for the last 64 bit
    # the last 64 bit will encode the length of the whole message being hashed
    length = length * 8
    block = b''
    if (add_one_at_the_start):
        block += unhexlify(b'80')
        zeroes_to_add = 63 - 8
    else:
        zeroes_to_add = 64 - 8

    zeroes_bytes = block + bytes([0 for i in range(0, zeroes_to_add)])
    block = zeroes_bytes + length.to_bytes(8, 'big')
    assert len(block) == 64
    return block


def pad_last_block(last_block, total_length_message):
    # pads the last block with appropriate padding, adds the +1 automatically
    # we assume that the block being passed has enough space to add the 8 bytes
    # required for the length and the 1 byte extra

    assert len(last_block) < 56
    total_length_message = total_length_message * 8
    # we want to add one bit followed by 7 zeroes the byte b'80' does that for us
    last_block += unhexlify(b'80')
    # make room for the length at the end, it has size 8 bytes (64 bits)
    bytes_to_add = 64 - (len(last_block) + 8)
    # add enough zeroes
    last_block += bytes([0 for i in range(0, bytes_to_add)])
    last_block += total_length_message.to_bytes(8, 'big')
    assert len(last_block) == 64
    return last_block


def pad_message(message, length=None):
    # given a message in bytes. Pads the last block according to the docs of 
    # sha256, returns a list of blocks where the last blocks are padded 
    # correctly
    assert isinstance(message, bytes)
    assert len(message) > 0

    if not length:
        length = len(message)

    blocks = [message[i: i + 64]
              for i in range(0, len(message), BLOCK_SIZE)]

    last_block = blocks[-1]
    if (len(last_block) < 56):
        last_block = pad_last_block(last_block, length)
        assert len(last_block) == 64
        return blocks[:len(blocks) - 1] + [last_block]
    else:
        if(len(last_block) == 64):
            return blocks + [get_extra_empty_block(length, True)]

        last_block += unhexlify(b'80')
        zeroes_bytes_to_add = 64 - (len(last_block))
        last_block += bytes([0 for i in range(0, zeroes_bytes_to_add)])
        assert len(last_block) == 64
        return blocks[:len(blocks) - 1] +\
                     [last_block, get_extra_empty_block(length)]


def compression_function(previous_hash, new_block):
    # compression function used in merkle damgard
    digest = [int(previous_hash[i: i + 8], 16)
              for i in range(0, len(previous_hash), 8)]
    assert isinstance(new_block, bytes)
    assert len(new_block) == BLOCK_SIZE

    new_hash = digest_to_hex(mutate(new_block, digest))
    return new_hash


def sha256(m):
    # merke-damgard construction
    assert isinstance(m, bytes)
    blocks = pad_message(m)
    prev_hash = digest_to_hex(INITIAL_HASH)

    for block in blocks:
        prev_hash = compression_function(prev_hash, block)
    return prev_hash


def test():
    import hashlib
    import random
    import string
    for i in range(0, 1000):
        random_string_function = lambda x: ''.join([random.choice(string.printable) for i in range(random.randint(1, x))])
        rnd = random_string_function(random.randint(1, 100))
        assert hashlib.sha256(rnd.encode()).hexdigest() == sha256(rnd.encode())

if __name__ == "__main__":
    test()
