#!/usr/local/bin/python

"""
stream.py

@author Elliot and Erica
"""

import sys
import random
from cryptography_utilities import (string_to_binary, file_to_binary,
    binary_to_file)

def psuedo_random_register_fn(key):
    """Provide a register function that gives the next bit in the
    keystream. In this case use the key to seed into python's
    pseudo-random number generator.
    """
    random.seed(key)
    def register_fn():
        return str(random.randint(0, 1))
    return register_fn

def xor_combiner(binary):
    """Collapse a sequence of bits into a single bit by XOR."""
    return '1' if reduce(lambda x, y: x != y, binary) else '0'

def setup_register(key, register_fn, size=50):
    """Generate an initial register with the key. If the key doesn't
    fill the minimum register size, call register_fn until it does.
    """
    binary_key = list(string_to_binary(key))
    if len(binary_key) < size:
        return binary_key + [register_fn()
                             for _ in range(size - len(binary_key))]
    else:
        return binary_key

def update_register(register, register_fn):
    """Nondestructively advance the bit register."""
    return register[1:] + [register_fn()]

def stream_cipher(binary_text, key, combiner_fn, register_fn):
    """Encrypt or decrypt a binary string of text by combining a
    maintained register with each successive bit of binary_text.

    :param binary_text: a string of 1s and 0s
    :param key: an alphanumeric password
    :param combiner_fn: takes the register and outputs a single bit
    :param register_fn: gives the next bit in the keystream
    """
    register = setup_register(key, register_fn)
    output = ''
    for bit in binary_text:
        register = update_register(register, register_fn)
        output += '1' if combiner_fn(register) != bit else '0'
    return output

def main(args):
    if len(args) != 4:
        print ('usage: {} <key> <input_file> <output_file>').format(args[0])
        return 1
    _, key, input_file, output_file = args
    binary_input = file_to_binary(input_file)
    converted_text = stream_cipher(binary_input, key, xor_combiner,
                                   psuedo_random_register_fn(key))
    binary_to_file(converted_text, output_file)

if __name__ == '__main__':
    main(sys.argv)
