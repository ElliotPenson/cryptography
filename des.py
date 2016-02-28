#!/usr/local/bin/python

"""
DES.py

@author Elliot and Erica
"""

import sys
from cryptography_utilities import (right_pad, left_pad,
    decimal_to_binary, binary_to_decimal, string_to_binary,
    file_to_binary, binary_to_file, shift_bits, xor)

S_BOXES = [# S-Box 1
           [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],
           # S-Box 2
           [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],
           # S-Box 3
           [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],
           # S-Box 4
           [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],
           # S-Box 5            
           [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],
           # S-Box 6        
           [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],
           # S-Box 7
           [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
           # S-Box 8
           [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]]

INITIAL_PERMUTATION = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
                       62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
                       57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
                       61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]

FINAL_PERMUTATION = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31,
                     38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29,
                     36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27,
                     34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25]

C_PERMUTATION = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10,
                 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25]

KEY_PERMUTATION_1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
                     10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
                     63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
                     14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]

KEY_PERMUTATION_2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
                     23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
                     41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
                     44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32]

KEY_SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

EXPANSION_PERMUTATION = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9,
                         8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17,
                         16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25,
                         24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1]

def format_key(key):
    """Convert a string key into 64 bits."""
    binary_representation = string_to_binary(key)
    below_64_bits = binary_representation[:64]
    return right_pad(below_64_bits, 64)

def make_blocks(plaintext, size=64):
    """Divide a string into a list of substrings. The final string in
    the result may be padded with zeroes to match the given size.
    """
    blocks = [plaintext[index:index + size]
              for index in xrange(0, len(plaintext), size)]
    blocks[-1] = right_pad(blocks[-1], size)
    return blocks

def permute(text, permutation, zero_based=False):
    """Shuffle a string based on a permutation. The permutation must be
    a list of indexes."""
    if not zero_based:
        permutation = [place - 1 for place in permutation]
    return ''.join([text[place] for place in permutation])

def split_block(blocktext):
    """Half a string of text. E.g. 'abcd' -> ('ab', 'cd')."""
    return (blocktext[:len(blocktext) / 2],
            blocktext[len(blocktext) / 2:])

def apply_s_box(six_bits, s_box):
    """Index into an s-box. Row is determined by the first a last bits,
    column by the middle four bits.
    """
    if len(six_bits) == 6:
        row = binary_to_decimal(six_bits[0] + six_bits[5])
        column = binary_to_decimal(six_bits[1:5])
        binary_value = decimal_to_binary(s_box[row][column])
        return left_pad(binary_value, size=4)
    else:
        raise ValueError("Incorrect number of bits for an s-box application.")

def generate_subkeys(key):
    """Split a 64-bit key into sixteen 48-bit subkeys - one for each
    round of the feistel structure.
    """
    shuffled_key = permute(key, KEY_PERMUTATION_1)
    ci, di = split_block(shuffled_key)
    subkeys = []
    for stage_shift in KEY_SHIFTS:
        ci = shift_bits(ci, stage_shift)
        di = shift_bits(di, stage_shift)
        subkeys.append(permute(ci + di, KEY_PERMUTATION_2))
    return subkeys

def feistel_function(half_block, key):
    """Perform confusion and diffusion on a 32-bit binary string."""
    expanded = permute(half_block, EXPANSION_PERMUTATION)
    xored = xor(expanded, key)
    b_sections = [xored[place:place + 6] for place in xrange(0, 48, 6)]
    c_sections = [apply_s_box(section, S_BOXES[number])
                  for number, section in enumerate(b_sections)]
    return permute(''.join(c_sections), C_PERMUTATION)

def feistel_scheme(text, subkeys):
    """Run the DES algorithm on a each block of the string input
    text. The subkeys parameter should be a list of sixteen 48-bit
    binary strings.
    """
    final_blocks = []
    for block in make_blocks(text):
        block = permute(block, INITIAL_PERMUTATION)
        left, right = split_block(block)
        for key in subkeys:
            right, left = xor(left, feistel_function(right, key)), right
        block = permute(right + left, FINAL_PERMUTATION)
        final_blocks.append(block)
    return ''.join(final_blocks)

def encrypt(text, key):
    """Generate binary ciphertext from binary plaintext with DES."""
    return feistel_scheme(text, generate_subkeys(key))

def decrypt(text, key):
    """Reveal binary plaintext from binary ciphertext with DES."""
    return feistel_scheme(text, list(reversed(generate_subkeys(key))))

def main(args):
    if len(args) != 5 or not args[1] in ['--encrypt', '--decrypt']:
        print ('usage: {} <--encrypt|--decrypt> <key> '
               '<input_file> <output_file>').format(args[0])
        return 1
    _, mode, key, input_file, output_file = args
    binary_input = file_to_binary(input_file)
    binary_key = format_key(key)
    if mode == '--encrypt':
        output = encrypt(binary_input, binary_key)
    else: # mode == '--decrypt'
        output = decrypt(binary_input, binary_key)
    binary_to_file(output, output_file)

if __name__ == '__main__':
    main(sys.argv)
