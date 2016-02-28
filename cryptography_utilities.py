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

def shift_bits(binary, amount):
    """Move the characters of the binary string to the left. Bits will
    be wrapped. E.g. shift_bits('1011', 1) -> '0111'.
    """
    return ''.join([binary[(place + amount) % len(binary)]
                    for place in range(len(binary))])

def xor(binary1, binary2):
    """Perform an XOR with the bits of two binary strings."""
    return ''.join(['1' if bit1 != bit2 else '0'
                    for bit1, bit2 in zip(binary1, binary2)])
