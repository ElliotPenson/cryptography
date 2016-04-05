#!/usr/local/bin/python

"""
AES.py

@author Elliot and Erica
"""

import sys
from cryptography_utilities import (right_pad, left_pad,
    decimal_to_binary, binary_to_decimal, string_to_binary,
    file_to_binary, binary_to_file, shift_bits_left,
    shift_bits_right, binary_and, xor, binary_to_string)

BYTE_LENGTH = 8

S_BOX = [['0x63', '0x7C', '0x77', '0x7B', '0xF2', '0x6B', '0x6F', '0xC5',
          '0x30', '0x01', '0x67', '0x2B', '0xFE', '0xD7', '0xAB', '0x76'],
         ['0xCA', '0x82', '0xC9', '0x7D', '0xFA', '0x59', '0x47', '0xF0',
          '0xAD', '0xD4', '0xA2', '0xAF', '0x9C', '0xA4', '0x72', '0xC0'],
         ['0xB7', '0xFD', '0x93', '0x26', '0x36', '0x3F', '0xF7', '0xCC',
          '0x34', '0xA5', '0xE5', '0xF1', '0x71', '0xD8', '0x31', '0x15'],
         ['0x04', '0xC7', '0x23', '0xC3', '0x18', '0x96', '0x05', '0x9A',
          '0x07', '0x12', '0x80', '0xE2', '0xEB', '0x27', '0xB2', '0x75'],
         ['0x09', '0x83', '0x2C', '0x1A', '0x1B', '0x6E', '0x5A', '0xA0',
          '0x52', '0x3B', '0xD6', '0xB3', '0x29', '0xE3', '0x2F', '0x84'],
         ['0x53', '0xD1', '0x00', '0xED', '0x20', '0xFC', '0xB1', '0x5B',
          '0x6A', '0xCB', '0xBE', '0x39', '0x4A', '0x4C', '0x58', '0xCF'],
         ['0xD0', '0xEF', '0xAA', '0xFB', '0x43', '0x4D', '0x33', '0x85',
          '0x45', '0xF9', '0x02', '0x7F', '0x50', '0x3C', '0x9F', '0xA8'],
         ['0x51', '0xA3', '0x40', '0x8F', '0x92', '0x9D', '0x38', '0xF5',
          '0xBC', '0xB6', '0xDA', '0x21', '0x10', '0xFF', '0xF3', '0xD2'],
         ['0xCD', '0x0C', '0x13', '0xEC', '0x5F', '0x97', '0x44', '0x17',
          '0xC4', '0xA7', '0x7E', '0x3D', '0x64', '0x5D', '0x19', '0x73'],
         ['0x60', '0x81', '0x4F', '0xDC', '0x22', '0x2A', '0x90', '0x88',
          '0x46', '0xEE', '0xB8', '0x14', '0xDE', '0x5E', '0x0B', '0xDB'],
         ['0xE0', '0x32', '0x3A', '0x0A', '0x49', '0x06', '0x24', '0x5C',
          '0xC2', '0xD3', '0xAC', '0x62', '0x91', '0x95', '0xE4', '0x79'],
         ['0xE7', '0xC8', '0x37', '0x6D', '0x8D', '0xD5', '0x4E', '0xA9',
          '0x6C', '0x56', '0xF4', '0xEA', '0x65', '0x7A', '0xAE', '0x08'],
         ['0xBA', '0x78', '0x25', '0x2E', '0x1C', '0xA6', '0xB4', '0xC6',
          '0xE8', '0xDD', '0x74', '0x1F', '0x4B', '0xBD', '0x8B', '0x8A'],
         ['0x70', '0x3E', '0xB5', '0x66', '0x48', '0x03', '0xF6', '0x0E',
          '0x61', '0x35', '0x57', '0xB9', '0x86', '0xC1', '0x1D', '0x9E'],
         ['0xE1', '0xF8', '0x98', '0x11', '0x69', '0xD9', '0x8E', '0x94',
          '0x9B', '0x1E', '0x87', '0xE9', '0xCE', '0x55', '0x28', '0xDF'],
         ['0x8C', '0xA1', '0x89', '0x0D', '0xBF', '0xE6', '0x42', '0x68',
          '0x41', '0x99', '0x2D', '0x0F', '0xB0', '0x54', '0xBB', '0x16']]

INVERSE_S_BOX = [['0x52', '0x09', '0x6A', '0xD5', '0x30', '0x36', '0xA5', '0x38',
                  '0xBF', '0x40', '0xA3', '0x9E', '0x81', '0xF3', '0xD7', '0xFB'],
                 ['0x7C', '0xE3', '0x39', '0x82', '0x9B', '0x2F', '0xFF', '0x87',
                  '0x34', '0x8E', '0x43', '0x44', '0xC4', '0xDE', '0xE9', '0xCB'],
                 ['0x54', '0x7B', '0x94', '0x32', '0xA6', '0xC2', '0x23', '0x3D',
                  '0xEE', '0x4C', '0x95', '0x0B', '0x42', '0xFA', '0xC3', '0x4E'],
                 ['0x08', '0x2E', '0xA1', '0x66', '0x28', '0xD9', '0x24', '0xB2',
                  '0x76', '0x5B', '0xA2', '0x49', '0x6D', '0x8B', '0xD1', '0x25'],
                 ['0x72', '0xF8', '0xF6', '0x64', '0x86', '0x68', '0x98', '0x16',
                  '0xD4', '0xA4', '0x5C', '0xCC', '0x5D', '0x65', '0xB6', '0x92'],
                 ['0x6C', '0x70', '0x48', '0x50', '0xFD', '0xED', '0xB9', '0xDA',
                  '0x5E', '0x15', '0x46', '0x57', '0xA7', '0x8D', '0x9D', '0x84'],
                 ['0x90', '0xD8', '0xAB', '0x00', '0x8C', '0xBC', '0xD3', '0x0A',
                  '0xF7', '0xE4', '0x58', '0x05', '0xB8', '0xB3', '0x45', '0x06'],
                 ['0xD0', '0x2C', '0x1E', '0x8F', '0xCA', '0x3F', '0x0F', '0x02',
                  '0xC1', '0xAF', '0xBD', '0x03', '0x01', '0x13', '0x8A', '0x6B'],
                 ['0x3A', '0x91', '0x11', '0x41', '0x4F', '0x67', '0xDC', '0xEA',
                  '0x97', '0xF2', '0xCF', '0xCE', '0xF0', '0xB4', '0xE6', '0x73'],
                 ['0x96', '0xAC', '0x74', '0x22', '0xE7', '0xAD', '0x35', '0x85',
                  '0xE2', '0xF9', '0x37', '0xE8', '0x1C', '0x75', '0xDF', '0x6E'],
                 ['0x47', '0xF1', '0x1A', '0x71', '0x1D', '0x29', '0xC5', '0x89',
                  '0x6F', '0xB7', '0x62', '0x0E', '0xAA', '0x18', '0xBE', '0x1B'],
                 ['0xFC', '0x56', '0x3E', '0x4B', '0xC6', '0xD2', '0x79', '0x20',
                  '0x9A', '0xDB', '0xC0', '0xFE', '0x78', '0xCD', '0x5A', '0xF4'],
                 ['0x1F', '0xDD', '0xA8', '0x33', '0x88', '0x07', '0xC7', '0x31',
                  '0xB1', '0x12', '0x10', '0x59', '0x27', '0x80', '0xEC', '0x5F'],
                 ['0x60', '0x51', '0x7F', '0xA9', '0x19', '0xB5', '0x4A', '0x0D',
                  '0x2D', '0xE5', '0x7A', '0x9F', '0x93', '0xC9', '0x9C', '0xEF'],
                 ['0xA0', '0xE0', '0x3B', '0x4D', '0xAE', '0x2A', '0xF5', '0xB0',
                  '0xC8', '0xEB', '0xBB', '0x3C', '0x83', '0x53', '0x99', '0x61'],
                 ['0x17', '0x2B', '0x04', '0x7E', '0xBA', '0x77', '0xD6', '0x26',
                  '0xE1', '0x69', '0x14', '0x63', '0x55', '0x21', '0x0C', '0x7D']]
def apply_s_box(eight_bits, s_box):
    """Index into an s-box. Row is determined by the first four bits,
    column by the second four bits.
    """
    if len(eight_bits) == 8:
        row = binary_to_decimal(eight_bits[0:4])
        column = binary_to_decimal(eight_bits[4:])
        binary_value = decimal_to_binary(int(s_box[row][column], 16))
        return left_pad(binary_value, size=8)
    else:
        raise ValueError("Incorrect number of bits for an s-box application.")

def byte_sub_transformation(matrix, s_box=S_BOX):
    return [[apply_s_box(byte, s_box) for byte in row]
            for row in matrix]

def shift_list(list, places):
    list_length = len(list)
    return [list[(places + i) % list_length]
            for i in range(list_length)]

def shift_row_transformation(matrix):
    return [shift_list(matrix[i], i)
            for i in range(len(matrix))]

def inverse_shift_row_transformation(matrix):
    "TODO make a shift_right"
    return [shift_list(matrix[i], 4 - i)
            for i in range(len(matrix))]

def multiply_by_x(binary):
    something = binary + '0'
    if something[0] == '1':
        something = xor(something, '100011011')
    return something[1:]

def gf_1(binary):
    return binary

def gf_x(binary):
    return multiply_by_x(binary)

def gf_x_1(binary):
    return xor(multiply_by_x(binary), binary)

def gf_x3_1(binary):
    return xor(multiply_by_x(multiply_by_x(multiply_by_x(binary))),
               binary)

def gf_x3_x_1(binary):
    return xor(multiply_by_x(multiply_by_x(multiply_by_x(binary))),
               multiply_by_x(binary),
               binary)

def gf_x3_x2_1(binary):
    return xor(multiply_by_x(multiply_by_x(multiply_by_x(binary))),
               multiply_by_x(multiply_by_x(binary)),
               binary)

def gf_x3_x2_x(binary):
    return xor(multiply_by_x(multiply_by_x(multiply_by_x(binary))),
               multiply_by_x(multiply_by_x(binary)),
               multiply_by_x(binary))

COLUMN_MIX = [[gf_x, gf_x_1, gf_1, gf_1],
              [gf_1, gf_x, gf_x_1, gf_1],
              [gf_1, gf_1, gf_x, gf_x_1],
              [gf_x_1, gf_1, gf_1, gf_x]]

INVERSE_COLUMN_MIX = [[gf_x3_x2_x, gf_x3_x_1, gf_x3_x2_1, gf_x3_1],
                      [gf_x3_1, gf_x3_x2_x, gf_x3_x_1, gf_x3_x2_1],
                      [gf_x3_x2_1, gf_x3_1, gf_x3_x2_x, gf_x3_x_1],
                      [gf_x3_x_1, gf_x3_x2_1, gf_x3_1, gf_x3_x2_x]]
    
def mix_column_transformation(matrix, column_mix=COLUMN_MIX):
    to_return = [[None, None, None, None],
                 [None, None, None, None],
                 [None, None, None, None],
                 [None, None, None, None]]
    # First row
    to_return[0][0] = xor(column_mix[0][0](matrix[0][0]),
                          column_mix[0][1](matrix[1][0]),
                          column_mix[0][2](matrix[2][0]),
                          column_mix[0][3](matrix[3][0]))
    to_return[0][1] = xor(column_mix[0][0](matrix[0][1]),
                          column_mix[0][1](matrix[1][1]),
                          column_mix[0][2](matrix[2][1]),
                          column_mix[0][3](matrix[3][1]))
    to_return[0][2] = xor(column_mix[0][0](matrix[0][2]),
                          column_mix[0][1](matrix[1][2]),
                          column_mix[0][2](matrix[2][2]),
                          column_mix[0][3](matrix[3][2]))
    to_return[0][3] = xor(column_mix[0][0](matrix[0][3]),
                          column_mix[0][1](matrix[1][3]),
                          column_mix[0][2](matrix[2][3]),
                          column_mix[0][3](matrix[3][3]))
    # Second row
    to_return[1][0] = xor(column_mix[1][0](matrix[0][0]),
                          column_mix[1][1](matrix[1][0]),
                          column_mix[1][2](matrix[2][0]),
                          column_mix[1][3](matrix[3][0]))
    to_return[1][1] = xor(column_mix[1][0](matrix[0][1]),
                          column_mix[1][1](matrix[1][1]),
                          column_mix[1][2](matrix[2][1]),
                          column_mix[1][3](matrix[3][1]))
    to_return[1][2] = xor(column_mix[1][0](matrix[0][2]),
                          column_mix[1][1](matrix[1][2]),
                          column_mix[1][2](matrix[2][2]),
                          column_mix[1][3](matrix[3][2]))
    to_return[1][3] = xor(column_mix[1][0](matrix[0][3]),
                          column_mix[1][1](matrix[1][3]),
                          column_mix[1][2](matrix[2][3]),
                          column_mix[1][3](matrix[3][3]))
    # Third row
    to_return[2][0] = xor(column_mix[2][0](matrix[0][0]),
                          column_mix[2][1](matrix[1][0]),
                          column_mix[2][2](matrix[2][0]),
                          column_mix[2][3](matrix[3][0]))
    to_return[2][1] = xor(column_mix[2][0](matrix[0][1]),
                          column_mix[2][1](matrix[1][1]),
                          column_mix[2][2](matrix[2][1]),
                          column_mix[2][3](matrix[3][1]))
    to_return[2][2] = xor(column_mix[2][0](matrix[0][2]),
                          column_mix[2][1](matrix[1][2]),
                          column_mix[2][2](matrix[2][2]),
                          column_mix[2][3](matrix[3][2]))
    to_return[2][3] = xor(column_mix[2][0](matrix[0][3]),
                          column_mix[2][1](matrix[1][3]),
                          column_mix[2][2](matrix[2][3]),
                          column_mix[2][3](matrix[3][3]))
    # Fourth row
    to_return[3][0] = xor(column_mix[3][0](matrix[0][0]),
                          column_mix[3][1](matrix[1][0]),
                          column_mix[3][2](matrix[2][0]),
                          column_mix[3][3](matrix[3][0]))
    to_return[3][1] = xor(column_mix[3][0](matrix[0][1]),
                          column_mix[3][1](matrix[1][1]),
                          column_mix[3][2](matrix[2][1]),
                          column_mix[3][3](matrix[3][1]))
    to_return[3][2] = xor(column_mix[3][0](matrix[0][2]),
                          column_mix[3][1](matrix[1][2]),
                          column_mix[3][2](matrix[2][2]),
                          column_mix[3][3](matrix[3][2]))
    to_return[3][3] = xor(column_mix[3][0](matrix[0][3]),
                          column_mix[3][1](matrix[1][3]),
                          column_mix[3][2](matrix[2][3]),
                          column_mix[3][3](matrix[3][3]))
    return to_return

def add_round_key(matrix1, matrix2):
    "XOR two matrices"
    return [[xor(element1, element2)
             for element1, element2 in zip(row1, row2)]
            for row1, row2 in zip(matrix1, matrix2)]

def binary_to_matrix(binary):
    return [[binary[index:index + 8]
             for index in range(group, len(binary), 32)]
            for group in [0, 8, 16, 24]]

def matrix_to_binary(matrix):
    return ''.join([matrix[column][row]
                    for row in range(4)
                    for column in range(4)])

def round_constant(column_number):
    return reduce(lambda acc, _: multiply_by_x(acc),
                  range((column_number - 4) / 4), '00000010')

def subkey_transformation(column, column_number):
    shifted = shift_list(column, 1)
    s_boxed = [apply_s_box(byte, S_BOX) for byte in shifted]
    return ([xor(s_boxed[0], round_constant(column_number))] +
            s_boxed[1:])

def rotate_matrix(matrix, size=4):
    return [[matrix[row][column] for row in range(size)]
            for column in range(size)]

def key_schedule(key):
    "Return a list of eleven subkeys."
    matrix = binary_to_matrix(key)
    w = [[matrix[column][row] for row in range(4)] for column in range(4)]
    
    def xor_columns(column1, column2):
        return [xor(element1, element2)
                for element1, element2
                in zip(column1, column2)]
    
    for column_number in range(4, 44):
        if column_number % 4 == 0:
            w.append(xor_columns(w[column_number - 4],
                                 subkey_transformation(w[column_number - 1],
                                                        column_number)))
        else:
            w.append(xor_columns(w[column_number - 4], w[column_number - 1]))

    return [rotate_matrix(w[index:index + 4])
            for index in range(0, 44, 4)]

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

def encrypt(binary_plaintext, binary_key):
    padded_plaintext = pad_plaintext(binary_plaintext, 128)
    subkeys = key_schedule(binary_key)
    final_blocks = []
    for block in block_split(padded_plaintext, 128):
        matrix = binary_to_matrix(block)
        matrix = add_round_key(matrix, subkeys[0])
        for round in range(1, 10):
            matrix = byte_sub_transformation(matrix)
            matrix = shift_row_transformation(matrix)
            matrix = mix_column_transformation(matrix)
            matrix = add_round_key(matrix, subkeys[round])
        matrix = byte_sub_transformation(matrix)
        matrix = shift_row_transformation(matrix)
        matrix = add_round_key(matrix, subkeys[-1])
        final_blocks.append(matrix_to_binary(matrix))
    return ''.join(final_blocks)

def decrypt(binary_ciphertext, binary_key):
    subkeys = list(reversed(key_schedule(binary_key)))
    final_blocks = []
    for block in block_split(binary_ciphertext, 128):
        matrix = binary_to_matrix(block)
        matrix = add_round_key(matrix, subkeys[0])
        matrix = inverse_shift_row_transformation(matrix)
        matrix = byte_sub_transformation(matrix, INVERSE_S_BOX)
        for round in range(1, 10):
            matrix = add_round_key(matrix, subkeys[round])
            matrix = mix_column_transformation(matrix, INVERSE_COLUMN_MIX)
            matrix = inverse_shift_row_transformation(matrix)
            matrix = byte_sub_transformation(matrix, INVERSE_S_BOX)
        matrix = add_round_key(matrix, subkeys[-1])
        final_blocks.append(matrix_to_binary(matrix))
    return unpad_plaintext(''.join(final_blocks))

def format_key(key, key_length=128):
    """Appropriately convert a string key into 64 bits. Oversized keys
    are truncated, undersized keys are padded with zeroes. A parity bit
    is also added to the end of each byte.
    """
    binary_key = string_to_binary(key)
    if len(binary_key) < key_length:
        return right_pad(binary_key, key_length)
    else:
        return binary_key[:key_length]

def main(args):
    if len(args) != 5 or not args[1] in ['--encrypt', '--decrypt']:
        print ('usage: {} <--encrypt|--decrypt> <key> '
               '<input_file> <output_file>').format(args[0])
        return 1
    _, mode, key, input_file, output_file = args
    binary_input = file_to_binary(input_file)
    if mode == '--encrypt':
        output = encrypt(binary_input, format_key(key))
    else: # mode == '--decrypt'
        output = decrypt(binary_input, format_key(key))
    binary_to_file(output, output_file)

if __name__ == '__main__':
    main(sys.argv)
