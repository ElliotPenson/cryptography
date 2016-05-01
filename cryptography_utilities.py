#!/usr/local/bin/python

"""
cryptography_utilities.py

@author Elliot and Erica
"""

import random

BYTE_LENGTH = 8

def decimal_to_binary(decimal):
    """Convert an integer into a binary string. E.g. 5 -> '101'."""
    return format(decimal, 'b')

def binary_to_decimal(binary):
    """Convert a binary string into an integer. E.g. '101' -> 5."""
    return int(binary, 2)

def hex_to_binary(hex):
    """Convert a hexadecimal string into a binary string. E.g. 'A1'
    -> '10100001'.
    """
    return decimal_to_binary(int(hex, 16))

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

def fermat_test(n):
    """Statistically test the primality of a number using the Fermat
    algorithm.
    """
    return (2**(n - 1) % n) == 1

def miller_rabin_test(n):
    """Statistically test the primality of a number using the Miller–Rabin
    algorithm.
    """
    k, m = 0, n - 1
    while True:
        if m % 2 != 0:
            break
        else:
            k += 1
            m /= 2

    b = 2**m % n

    if (b - n) == -1 or b == 1:
        return True

    b = b**2 % n
    if (b - n) == -1:
        return True

    for _ in range(2, k):
        b = b**2 % n
        if (b - n) == -1:
            return True
        if b == 1:
            return False
    return False

def primep(n):
    """Combine both the Fermat and Miller-Rabin primality tests into a
    single function. The predicate should indicate primality with a high
    likelihood of success.
    """
    return fermat_test(n) and miller_rabin_test(n)

def random_number(bits):
    """Generate a random integer that will cleanly fit in a number of bits."""
    max, min = 2**bits - 1, 2**(bits - 1)
    return random.randint(min, max)

def random_prime(bits):
    """Generate a random prime that will cleanly fit in a number of bits."""
    while True:
        n = random_number(bits)
        if n % 2 == 0 or n % 3 == 0:
            continue
        if primep(n):
            return n

def coprimep(x, y):
    return gcd(x, y) == 1

def gcd(a, b):
    """Greatest common divisor of x and y computed with the Euclidean
    algorithm.
    """
    return gcd(b, a % b) if b else a

def extended_gcd(a, b):
    """Extended Euclidean algorithm. Provides a tuple of (g, x, y)
    from ax + by = gcd(a, b). Function taken from Wikibooks.
    """
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modular_inverse(x, modulus):
    """Compute x^-1 (mod modulus)."""
    return extended_gcd(x, modulus)[1]

def modular_sqrt(x, modulus):
    """Compute sqrt(x) (mod modulus). The modulus must be a prime
    number.
    """
    potential_sqrt = pow(x, ((modulus + 1) / 4), modulus)
    if (potential_sqrt**2 % modulus) == (x % modulus):
        return int(potential_sqrt)
    else:
        raise AssertionError('Composite modulus')

def random_relative_prime(prime, bits):
    """Find a number relatively prime (gcd of 1) number randomly."""
    max, min = 2**bits - 1, 2**(bits - 1)
    while True:
        random_int = random.randint(min, max)
        if gcd(random_int, prime) == 1:
            return random_int

def group_exponentiation(base, power, n):
    """Raise a number to a given power in the GF(2^8) finite field."""
    bits = decimal_to_binary(power)
    result = 1
    for bit_index, bit in zip(range(len(bits) - 1, -1, -1), bits):
        if bit == '1':
            result *= base**(2**bit_index) % n
    return result % n
