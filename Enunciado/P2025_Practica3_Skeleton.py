#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import random
import hashlib
from sympy import isprime, mod_inverse


# --- IMPLEMENTATION GOES HERE -----------------------------------------------
#  Student helpers (functions, constants, etc.) can be defined here, if needed


def generate_prime_candidate(length):

    """
    EXERCISE 1.1: Create a random prime value 
    :return: Ramdom prime values 
    """

    #### IMPLEMENTATION GOES HERE ####

    
     ##################################
    return p

def mcd(a, b):
    """
    EXERCISE 1.2: Calculate mcd 'Màxim Comú divisor' of defined values 
    """
    #### IMPLEMENTATION GOES HERE ####

    ##################################        
    return a

def generate_keypair(length):
    """
    EXERCISE 1.2: Generate pair of radom pairs p and q.
    Calculate 'n' and 'phi' values
    Choose 'e' value with required RSA especifications.
    Calculate 'd' value according with RSA especifications.  
    RETURN pair of Kpub as (e,n) and Kpriv (d,n)
    """
    #### IMPLEMENTATION GOES HERE ####

    ##################################º
    return ((e, n), (d, n))

def encrypt(Kpub, m):
    #### IMPLEMENTATION GOES HERE ####

    ##################################
    return cipher

def decrypt(Kpriv, ciphertext):
    #### IMPLEMENTATION GOES HERE ####

    #################################
    return plain

def RSA_sign(Kpriv, m):
    #### IMPLEMENTATION GOES HERE ####

    ##################################
    print("\n\n El resultat es: ",result)
    return result


def Validate_Sign(Kpub, m, s):
    #### IMPLEMENTATION GOES HERE ####

    ##################################
    return bool(mprima == m)

def calcular_sha256(message):

    return hash_hex

def segona_preimatge(message):

    return None

if __name__ == '__main__':
    length = 1024  # Longitud de les claus en bits
    public, private = generate_keypair(length)
    
    print("Clau pública:", public)
    print("Clau privada:", private)
    
    message = 123456789123456789123456789
    encrypted_msg = encrypt(public, message)
    decrypted_msg = decrypt(private, encrypted_msg)

    s = RSA_sign(private, message)
    validació=Validate_Sign(public,message,s)
    print("Validació signatura: ",validació)

    hash_resultat = calcular_sha256(message)
    print("El hash SHA-256 de '{texto}' es: ", hash_resultat)

    resultat = segona_preimatge(message)
    if resultat:
        print("Segona preimatge trobada: ", resultat)
    else:
        print("Cap segona preimatge trobada.")










