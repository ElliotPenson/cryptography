#!/usr/local/bin/python

"""
dh.py

@author Elliot and Erica
"""

from __future__ import division

import random

from math import sqrt

from cryptography_utilities import (random_number, random_prime, coprimep,
    extended_gcd, modular_inverse, modular_sqrt)

CURVE25519_PRIME = 2**255 - 19

CURVE25519_A = (486662**3 / 3) - (2*486662 / 3) + 1

CURVE25519_B = -(486662**3 / 27) + (486662**2 / 9) - (486662 / 3)

CURVE25519_BASE_X = 9

CURVE25519_BASE_Y = modular_sqrt(CURVE25519_BASE_X**3 +
                                 486662 * CURVE25519_BASE_X**2 +
                                 CURVE25519_BASE_X,
                                 CURVE25519_PRIME)

class DiffieHellman(object):
    """Standard Diffie-Hellman implementation using the multiplicative
    group of integers modulo a randomly generated prime.
    """

    def __init__(self, bits=32):
        """Setup with prime modulus and base number public keys and a
        secret random integer smaller than the modulus."""
        p = random_prime(bits)
        alpha = random_number(bits) % p
        if coprimep(p - 1, alpha):
            self.modulus = p
            self.base = alpha
            self.private_key = random.randint(1, p - 2)
            self.mutual_secret = None # defined in give_key
        else:
            type(self)(bits)

    def public_keys(self):
        """Return a tuple of (modulus, base)."""
        return self.modulus, self.base

    def get_key(self):
        """Compute base^private_key (mod p) for the other party."""
        return pow(self.base, self.private_key, self.modulus)

    def give_key(self, key):
        """Send a computed base^private_key (mod p) to this party."""
        self.mutual_secret = pow(key, self.private_key, self.modulus)

class EllipticDiffieHellman(DiffieHellman):
    """Diffie-Hellman implementation that follows an elliptic curve group.
    The specific curve used is Curve25519 -> y^2 = x^3 + 486662x^2 + x.
    """

    def __init__(self):
        self.private_key = random.randint(1, CURVE25519_PRIME - 2)

    def public_keys(self):
        """Return a tuple of curve constants (base-x, base-y, modulus)."""
        return CURVE25519_BASE_X, CURVE25519_BASE_Y, CURVE25519_PRIME

    def get_key(self):
        """Compute self.private_key(base_x, base_y) [add base_x, base_y
        together self.private_key times] for the other party."""
        result_x, result_y = CURVE25519_BASE_X, CURVE25519_BASE_Y
        for _ in xrange(self.private_key):
            result_x, result_y = point_add(result_x, result_y,
                                           CURVE25519_BASE_X, CURVE25519_BASE_Y,
                                           CURVE25519_PRIME)
        return result_x, result_y

    def give_key(self, key):
        """Send a computed self.private_key(key) [add key together
        self.private_key times] to this party.
        """
        result_x, result_y = key
        for _ in xrange(self.private_key):
            result_x, result_y = point_add(result_x, result_y,
                                           key[0], key[1],
                                           CURVE25519_PRIME)
        self.mutual_secret = result_x, result_y

def point_add(x1, y1, x2, y2, p):
    """Total two points on an elliptic curve (mod p). We assume that
    x1 == x2 and y1 == y2.
    """
    if x1 == x2 and y1 == y2:
        slope = ((3 * x1**2 + CURVE25519_B) * modular_inverse(2 * y1, p)) % p
    else:
        slope = ((y2 - y1) * modular_inverse(x2 - x1, p)) % p
    x3 = (slope**2 - x1 - x2) % p
    y3 = (slope * (x1 - x3) - y1) % p
    return (x3, y3)
