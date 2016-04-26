#!/usr/local/bin/python

"""
RSA.py

@author Elliot and Erica
"""

import random
from cryptography_utilities import (block_split, decimal_to_binary,
    binary_to_decimal, gcd, extended_gcd, random_prime, left_pad,
    pad_plaintext, unpad_plaintext, random_relative_prime,
    group_exponentiation)

MODULUS_BITS = 16

def key_generation():
    """Return a tuple of (modulus, public_key, private_key). The size of
    modulus (and associated primes) is determined by the MODULUS_BITS
    global.
    """
    prime1 = random_prime(MODULUS_BITS / 2)
    prime2 = random_prime(MODULUS_BITS / 2)
    modulus = prime1 * prime2
    totient = (prime1 - 1) * (prime2 - 1)
    public_key = random_relative_prime(totient, MODULUS_BITS / 2)
    if extended_gcd(public_key, totient)[1] < 0:
        private_key = extended_gcd(public_key, totient)[1] + totient
    else:
        private_key = extended_gcd(public_key, totient)[1]
    return modulus, public_key, private_key

def plaintext_block_size():
    """Determine a block size using the MODULUS_BITS global. The value
    will be a multiple of eight and less than MODULUS_BITS.
    """
    return (MODULUS_BITS - 1) - ((MODULUS_BITS - 1) % 8)

def rsa_exponentiation(text, modulus, key):
    """Perform modular exponentiation of a message based on a key. I.E.
    (text^k) = text (mod modulus).
    """
    integer_transformation = pow(binary_to_decimal(text), key, modulus)
    return decimal_to_binary(integer_transformation)

def encrypt(binary_plaintext, modulus, public_key):
    """Generate binary ciphertext from binary plaintext with RSA."""
    padded_plaintext = pad_plaintext(binary_plaintext, plaintext_block_size())
    return ''.join(left_pad(rsa_exponentiation(block, modulus, public_key),
                            MODULUS_BITS)
                   for block in block_split(padded_plaintext,
                                            plaintext_block_size()))

def decrypt(binary_ciphertext, modulus, private_key):
    """Reveal binary plaintext from binary ciphertext with RSA."""
    plaintext = ''.join(left_pad(rsa_exponentiation(block, modulus, private_key),
                                 plaintext_block_size())
                        for block in block_split(binary_ciphertext, MODULUS_BITS))
    return unpad_plaintext(plaintext)
