"""
block.py

@author Elliot and Erica
"""

def generate_key():
    pass

def number_list(string):
    alphabet = 'abcdefghijklmnopqrstuvwxyz'
    letter_map = {letter: number for number, letter in enumerate(alphabet)}
    return [letter_map[char] for char in string]

def hill_cipher_encrypt(plain_text, key):
    if not len(plain_text) % 3 == 0:
        plain_text += 'X' * len(plain_text) % 3
    
def hill_cipher_decrypt(cipher_text, key):
    pass
