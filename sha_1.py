#!/usr/local/bin/python

"""
sha_1.py

@author Elliot and Erica
"""

from cryptography_utilities import (wrap_bits_left, decimal_to_binary,
    binary_to_decimal, pad_plaintext, block_split, bitwise_and,
    bitwise_or, bitwise_xor, bitwise_not, hex_to_binary)

BLOCKSIZE = 512

SUB_BLOCKSIZE = 32

SHA_1_INTERVALS = 80

def add(*binaries):
    """Execute modular arithmetic mod 2^32. Input may consist of any
    number of binary strings.
    """
    total = 0
    for binary in binaries:
        total += binary_to_decimal(binary) % 2**32
    return decimal_to_binary(total % 2**32)

def mixing_operation(interval, b, c, d):
    """Perform one of four operations, based on the interval. The b, c, and
    d arguments are SHA-1 sub-registers.
    """
    if 0 <= interval <= 19:
        return bitwise_or(bitwise_and(b, c),
                          bitwise_and(bitwise_not(b), d))
    elif interval <= 39:
        return bitwise_xor(b, c, d)
    elif interval <= 59:
        return bitwise_or(bitwise_and(b, c),
                          bitwise_and(b, d),
                          bitwise_and(c, d))
    elif interval <= 79:
        return bitwise_xor(b, c, d)
    else:
        raise Exception('Interval out of bounds')

def round_constant(interval):
    """Return one of four binary string constants, based on the interval."""
    if 0 <= interval <= 19:
        return hex_to_binary('5A827999')
    elif interval <= 39:
        return hex_to_binary('6ED9EBA1')
    elif interval <= 59:
        return hex_to_binary('8F1BBCDC')
    elif interval <= 79:
        return hex_to_binary('CA62C1D6')
    else:
        raise Exception('Interval out of bounds')

def sha_1_expansion(block):
    """Take a 512 bit binary message and convert it into a series of
    32 bit blocks.
    """
    sub_blocks = block_split(block, SUB_BLOCKSIZE)
    for interval in xrange(len(sub_blocks), SHA_1_INTERVALS):
        new_sub_block = bitwise_xor(sub_blocks[interval - 3],
                                    sub_blocks[interval - 8],
                                    sub_blocks[interval - 14],
                                    sub_blocks[interval - 16])
        sub_blocks.append(wrap_bits_left(new_sub_block, 1))
    return sub_blocks

def sha_1_compression(sub_registers, sub_blocks):
    """Combines a series of sub_blocks into a single 160-bit binary
    string. The sub-registers and sub_blocks parameters should be
    collections of 32-bit binary strings.
    """
    a, b, c, d, e = sub_registers
    for interval in xrange(SHA_1_INTERVALS):
        new_a = add(wrap_bits_left(a, 5),
                    mixing_operation(interval, b, c, d),
                    e,
                    sub_blocks[interval],
                    round_constant(interval))
        e = d
        d = c
        c = wrap_bits_left(b, 30)
        b = a
        a = new_a
    return map(add, sub_registers, [a, b, c, d, e])

def sha_1(binary_message):
    """SHA-1 cryptographic hash function. Take a binary string of any
    length and output an obfuscated 160-bit binary hash."""
    padded_message = pad_plaintext(binary_message, BLOCKSIZE)
    sub_registers = [hex_to_binary(initial_register)
                     for initial_register
                     in ['67452301', 'EFCDAB89', '98BADCFE',
                         '10325476', 'C3D2E1F0']]
    for block in block_split(padded_message, BLOCKSIZE):
        sub_blocks = sha_1_expansion(block)
        sub_registers = sha_1_compression(sub_registers, sub_blocks)
    return ''.join(sub_registers)
