#!/usr/local/bin/python

"""
cryptography_utilities.py

@author Elliot and Erica
"""

BYTE_LENGTH = 8

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
    """Add a specific number of zeroes to the end of a binary string."""
    return right_pad(binary[amount:], len(binary))

def shift_bits_right(binary, amount):
    """Move the bits of a binary string to the right while maintaining
    the sign bit on the left.
    """
    sign_bit = binary[0]
    return (sign_bit * amount) + binary[:-amount]

def bitwise_operation(operation, binaries):
    """Generally apply a function to a list of binary strings. The
    operation should take two bit characters as input and output a
    single bit character.
    """
    final_length = min(map(len, binaries))
    return ''.join(reduce(operation,
                          map(lambda binary: binary[index],
                                  binaries))
                   for index in range(final_length))

def bitwise_xor(*binaries):
    """Perform an XOR with the bits of any number of binary strings. The
    output's final length is equal to the shortest binary string.
    """
    def bit_xor(bit1, bit2):
        return '1' if int(bit1) != int(bit2) else '0'
    return bitwise_operation(bit_xor, binaries)

def bitwise_and(*binaries):
    """Perform an AND with the bits of any number of binary strings. The
    output's final length is equal to the shortest binary string.
    """
    def bit_and(bit1, bit2):
        return '1' if int(bit1) & int(bit2) else '0'
    return bitwise_operation(bit_and, binaries)

def bitwise_or(*binaries):
    """Perform an OR with the bits of any number of binary strings. The
    output's final length is equal to the shortest binary string.
    """
    def bit_or(bit1, bit2):
        return '1' if int(bit1) | int(bit2) else '0'
    return bitwise_operation(bit_or, binaries)

def bitwise_not(binary):
    """Perform a unary NOT operation on the bits of a binary string."""
    return ''.join('1' if bit == '0' else '0' for bit in binary)

def pad_plaintext(text, block_size=64):
    """Make the length of the text evenly divisible by the block size by
    potentially padding with zeroes. The last byte of the result denotes
    the number of bytes added.
    """
    padding_amount = block_size - (len(text) % block_size)
    return text + left_pad(decimal_to_binary(padding_amount / BYTE_LENGTH),
                           padding_amount)

def unpad_plaintext(text):
    """Remove padding bits. The last byte of the text should indicate
    the number of bits to get rid of.
    """
    padding_amount = binary_to_decimal(text[-BYTE_LENGTH:])
    return text[:-(padding_amount * BYTE_LENGTH)]

def block_split(text, block_size=64):
    """Divide a string into a list of substrings.
    PRECONDITION: text % block_size == 0"""
    return [text[index:index + block_size]
            for index in xrange(0, len(text), block_size)]

def rotate(list, places):
    """Shift the elements in a list. A positive place will move the list
    to the left, a negative place to the right."""
    return list[places:] + list[:places]
