#!/usr/bin/env python3

# Homework Number: 6
# Name: Elias Talcott
# ECN Login: etalcott
# Due Date: March 3, 2020

from BitVector import *
import PrimeGenerator
import sys

###
## Call syntax:
## python3 rsa.py -g p.txt q.txt
## python3 rsa.py -e message.txt p.txt q.txt encrypted.txt
## python3 rsa.py -d encrypted.txt p.txt q.txt decrypted.txt
###

BLOCKSIZE = 128

###
## Calculate gcd
###
def gcd(a, b):
    while (b != 0):
        (a, b) = (b, a % b)
    return a


###
## Generate keys for RSA
###
def gen_keys(e):
    # Generate p and q
    generator = PrimeGenerator.PrimeGenerator(bits=128)
    p = generator.findPrime()
    q = generator.findPrime()

    # Make sure p and q are valid given e
    while gcd(p - 1, e) != 1:
        p = generator.findPrime()
    while gcd(q - 1, e) != 1 or q == p:
        q = generator.findPrime()
    return p, q


###
## RSA Encrypt
###
def encrypt(plaintext_bv, p, q, e):
    # Pad message to multiple of BLOCKSIZE bits
    if len(plaintext_bv) % BLOCKSIZE != 0:
        plaintext_bv.pad_from_right(BLOCKSIZE - len(plaintext_bv) % BLOCKSIZE)

    # Encrypt message one block at a time and add to ciphertext
    ciphertext_bv = BitVector(size = 0)
    for i in range(len(plaintext_bv) // BLOCKSIZE):
        bv = plaintext_bv[i * BLOCKSIZE : (i + 1) * BLOCKSIZE]
        bv.pad_from_left(BLOCKSIZE)
        ciphertext_bv += BitVector(size = BLOCKSIZE * 2, intVal = pow(int(bv), e, p * q))

    # Write encrypted message in hex
    return ciphertext_bv.get_bitvector_in_hex()


###
## RSA Decrypt
###
def decrypt(ciphertext_bv, p, q, e):
    # Calculate decryption exponent
    modulus_bv = BitVector(intVal = (p - 1) * (q - 1))
    e_bv = BitVector(intVal = e)
    d = int(e_bv.multiplicative_inverse(modulus_bv))

    # Decrypt ciphertext one block at a time and add to plaintext with padding removed
    plaintext_bv = BitVector(size = 0)
    for i in range(len(ciphertext_bv) // (BLOCKSIZE * 2)):
        bv = ciphertext_bv[i * BLOCKSIZE * 2 : (i + 1) * BLOCKSIZE * 2]
        bv = BitVector(size = BLOCKSIZE * 2, intVal = pow(int(bv), d, p * q))
        plaintext_bv += bv[BLOCKSIZE:]

    # Return encrypted message in hex
    return plaintext_bv.get_text_from_bitvector()


if __name__ == "__main__":
    e_val = 65537
    # Generate keys
    if len(sys.argv) == 4 and sys.argv[1] == "-g":
        pval, qval = gen_keys(e_val)
        with open(sys.argv[2], "w") as fp:
            fp.write(str(pval))
        with open(sys.argv[3], "w") as fq:
            fq.write(str(qval))
    # Encrypt
    elif len(sys.argv) == 6 and sys.argv[1] == "-e":
        with open(sys.argv[2]) as fpin:
            message_bv = BitVector(textstring = fpin.read())
        with open(sys.argv[3]) as fp:
            p_val = int(fp.read())
        with open(sys.argv[4]) as fq:
            q_val = int(fq.read())
        ciphertext = encrypt(message_bv, p_val, q_val, e_val)
        with open(sys.argv[5], "w") as fpout:
            fpout.write(ciphertext)
    # Decrypt
    elif len(sys.argv) == 6 and sys.argv[1] == "-d":
        with open(sys.argv[2]) as fpin:
            message_bv = BitVector(hexstring = fpin.read())
        with open(sys.argv[3]) as fp:
            p_val = int(fp.read())
        with open(sys.argv[4]) as fq:
            q_val = int(fq.read())
        plaintext = decrypt(message_bv, p_val, q_val, e_val)
        with open(sys.argv[5], "w") as fpout:
            fpout.write(plaintext)
    else:
        sys.exit("Wrong arguments!")