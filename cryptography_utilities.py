#!/usr/local/bin/python

"""
cryptography_utilities.py

@author Elliot and Erica
"""

def decimal_to_binary(decimal):
    """Convert an integer into a binary string. E.g. 5 -> '101'."""
    return format(decimal, 'b')

def binary_to_decimal(binary):
    """Convert a binary string into an integer. E.g. '101' -> 5."""
    return int(binary, 2)

def string_to_binary(string):
    """Coerce a string of text into a binary string."""
    return ''.join([left_pad(decimal_to_binary(ord(char)), size=8)
                    for char in string])

def binary_to_string(binary):
    """Coerce a binary string into a string of text."""
    return ''.join([chr(binary_to_decimal(binary[place:place + 8]))
                    for place in xrange(0, len(binary), 8)])

def file_to_binary(path):
    """Open a file and dump the contents into a binary string."""
    with open(path, 'r') as f:
        return string_to_binary(f.read())

def binary_to_file(text, path):
    """Write a binary string into a file as ASCII text."""
    with open(path, 'w') as f:
        f.write(binary_to_string(text))

def left_pad(string, size):
    """Add zeros to the front of a string to reach a certain length."""
    return string.zfill(size)

def right_pad(string, size):
    """Add zeros to the end of a string to reach a certain length."""
    return string.ljust(size, '0')

def wrap_bits_left(binary, amount):
    """Move the characters of the binary string to the left. Bits will
    be wrapped. E.g. shift_bits('1011', 1) -> '0111'.
    """
    return ''.join([binary[(place + amount) % len(binary)]
                    for place in range(len(binary))])

def wrap_bits_right(binary, amount):
    """Move the characters of the binary string to the left. Bits will
    be wrapped. E.g. shift_bits('1011', 1) -> '0111'.
    """
    return ''.join([binary[(place - amount) % len(binary)]
                    for place in range(len(binary))])

def shift_bits_left(binary, amount):
    return right_pad(binary[amount:], len(binary))

def shift_bits_right(binary, amount):
    sign_bit = binary[0]
    return (sign_bit * amount) + binary[:-amount]

def xor(*binaries):
    """Perform an XOR with the bits of two binary strings."""
    def single_bit_xor(bit1, bit2):
        return '1' if int(bit1) != int(bit2) else '0'
    final_length = min(map(len, binaries))
    return ''.join([reduce(single_bit_xor,
                           map(lambda binary: binary[index],
                                   binaries))
                    for index in range(final_length)])

def binary_and(binary1, binary2):
    return ''.join(['1' if int(bit1) & int(bit2) else '0'
                    for bit1, bit2 in zip(binary1, binary2)])
