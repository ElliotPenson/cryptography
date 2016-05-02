"""
hill_cipher.py

@author Elliot and Erica
"""

import random
import numpy as np
from cryptography_utilities import (gcd, extended_gcd)

ALPHABET = 'abcdefghijklmnopqrstuvwxyz'
ALPHABET_SIZE = len(ALPHABET)
N = 3
TOTIENT_26 = 12

def random_matrix(size=N):
    """Generate a NxN matrix filled with random integers"""
    array = [[random.randint(0, ALPHABET_SIZE - 1)
              for _ in range(size)]
             for _ in range(size)]
    return np.matrix(array)

def valid_key(matrix):
    """Determine if the given matrix can be used as a key"""
    return gcd(int(np.linalg.det(matrix)), ALPHABET_SIZE) == 1

def generate_key(size=N):
    """Return a NxN matrix filled with random integers that qualifies
    as a valid key.
    """
    matrix = random_matrix()
    while not valid_matrix(matrix):
        matrix = random_matrix()
    return matrix

def to_int(char):
    """Using ALPHABET, find the numeric representation of the given
    character.
    """
    char_map = {char: number for number, char in enumerate(ALPHABET)}
    return char_map[char]

def to_char(integer):
    """Using ALPHABET, find the character representation of the given
    integer.
    """
    integer_map = {number: char for number, char in enumerate(ALPHABET)}
    return integer_map[integer]

def number_matrix(string):
    """Convert a string into an integer matrix."""
    row = 0
    array = [[] for _ in range(N)]
    for char in make_correct_length(string):
        array[row].append(to_int(char))
        row = (row + 1) % N
    return np.matrix(array)

def make_correct_length(string):
    """Add x characters if the input string cannot be split into even
    blocks.
    """
    if not len(string) % N == 0:
        string += 'x' * (N - (len(string) % N))
    return string

def modular_inverse(number):
    """Calculate the modular multiplicative inverse of a number."""
    gcd, x, y = extended_gcd(ALPHABET_SIZE, number)
    if y < 0:
        return y + 26
    else:
        return y

def switch_key(key):
    """Change an encryption key into a decryption key or
    vice-versa.
    """
    key_determinant = int(np.linalg.det(key))
    inverse = np.linalg.inv(key)
    adjugate = np.multiply(inverse, key_determinant)
    raw_switch = np.multiply(modular_inverse(key_determinant),
                             adjugate)
    modder = np.vectorize(lambda n: int(n) % 26)
    return modder(raw_switch)

def hill_cipher_encrypt(plain_text, key):
    """Determine cipher text given plain text. The key should be an
    NxN matrix.
    """
    cipher_matrix = np.dot(key, number_matrix(plain_text))
    cipher_text = ''
    for number in np.nditer(cipher_matrix):
        cipher_text += to_char(number % ALPHABET_SIZE)
    return cipher_text
    
def hill_cipher_decrypt(cipher_text, key, encryption_key=False):
    """Determine plain text given cipher text. The key should be an
    NxN matrix.
    """
    if encryption_key:
        key = switch_key(key)
    plain_matrix = np.dot(key, number_matrix(cipher_text))
    plain_text = ''
    for number in np.nditer(plain_matrix):
        plain_text += to_char(number % ALPHABET_SIZE)
    return plain_text
