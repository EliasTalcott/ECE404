#!/usr/bin/env python3

# Homework Number: 7
# Name: Elias Talcott
# ECN Login: etalcott
# Due Date: March 12, 2020

from BitVector import *

###
## Call syntax: python3 sha512.py input.txt hash.txt
###

BLOCKSIZE = 1024
WORDSIZE = 64
K = [BitVector(hexstring = "428a2f98d728ae22"), BitVector(hexstring = "7137449123ef65cd"), BitVector(hexstring = "b5c0fbcfec4d3b2f"), BitVector(hexstring = "e9b5dba58189dbbc"),
     BitVector(hexstring = "3956c25bf348b538"), BitVector(hexstring = "59f111f1b605d019"), BitVector(hexstring = "923f82a4af194f9b"), BitVector(hexstring = "ab1c5ed5da6d8118"),
     BitVector(hexstring = "d807aa98a3030242"), BitVector(hexstring = "12835b0145706fbe"), BitVector(hexstring = "243185be4ee4b28c"), BitVector(hexstring = "550c7dc3d5ffb4e2"),
     BitVector(hexstring = "72be5d74f27b896f"), BitVector(hexstring = "80deb1fe3b1696b1"), BitVector(hexstring = "9bdc06a725c71235"), BitVector(hexstring = "c19bf174cf692694"),
     BitVector(hexstring = "e49b69c19ef14ad2"), BitVector(hexstring = "efbe4786384f25e3"), BitVector(hexstring = "0fc19dc68b8cd5b5"), BitVector(hexstring = "240ca1cc77ac9c65"),
     BitVector(hexstring = "2de92c6f592b0275"), BitVector(hexstring = "4a7484aa6ea6e483"), BitVector(hexstring = "5cb0a9dcbd41fbd4"), BitVector(hexstring = "76f988da831153b5"),
     BitVector(hexstring = "983e5152ee66dfab"), BitVector(hexstring = "a831c66d2db43210"), BitVector(hexstring = "b00327c898fb213f"), BitVector(hexstring = "bf597fc7beef0ee4"),
     BitVector(hexstring = "c6e00bf33da88fc2"), BitVector(hexstring = "d5a79147930aa725"), BitVector(hexstring = "06ca6351e003826f"), BitVector(hexstring = "142929670a0e6e70"),
     BitVector(hexstring = "27b70a8546d22ffc"), BitVector(hexstring = "2e1b21385c26c926"), BitVector(hexstring = "4d2c6dfc5ac42aed"), BitVector(hexstring = "53380d139d95b3df"),
     BitVector(hexstring = "650a73548baf63de"), BitVector(hexstring = "766a0abb3c77b2a8"), BitVector(hexstring = "81c2c92e47edaee6"), BitVector(hexstring = "92722c851482353b"),
     BitVector(hexstring = "a2bfe8a14cf10364"), BitVector(hexstring = "a81a664bbc423001"), BitVector(hexstring = "c24b8b70d0f89791"), BitVector(hexstring = "c76c51a30654be30"),
     BitVector(hexstring = "d192e819d6ef5218"), BitVector(hexstring = "d69906245565a910"), BitVector(hexstring = "f40e35855771202a"), BitVector(hexstring = "106aa07032bbd1b8"),
     BitVector(hexstring = "19a4c116b8d2d0c8"), BitVector(hexstring = "1e376c085141ab53"), BitVector(hexstring = "2748774cdf8eeb99"), BitVector(hexstring = "34b0bcb5e19b48a8"),
     BitVector(hexstring = "391c0cb3c5c95a63"), BitVector(hexstring = "4ed8aa4ae3418acb"), BitVector(hexstring = "5b9cca4f7763e373"), BitVector(hexstring = "682e6ff3d6b2b8a3"),
     BitVector(hexstring = "748f82ee5defb2fc"), BitVector(hexstring = "78a5636f43172f60"), BitVector(hexstring = "84c87814a1f0ab72"), BitVector(hexstring = "8cc702081a6439ec"),
     BitVector(hexstring = "90befffa23631e28"), BitVector(hexstring = "a4506cebde82bde9"), BitVector(hexstring = "bef9a3f7b2c67915"), BitVector(hexstring = "c67178f2e372532b"),
     BitVector(hexstring = "ca273eceea26619c"), BitVector(hexstring = "d186b8c721c0c207"), BitVector(hexstring = "eada7dd6cde0eb1e"), BitVector(hexstring = "f57d4f7fee6ed178"),
     BitVector(hexstring = "06f067aa72176fba"), BitVector(hexstring = "0a637dc5a2c898a6"), BitVector(hexstring = "113f9804bef90dae"), BitVector(hexstring = "1b710b35131c471b"),
     BitVector(hexstring = "28db77f523047d84"), BitVector(hexstring = "32caab7b40c72493"), BitVector(hexstring = "3c9ebe0a15c9bebc"), BitVector(hexstring = "431d67c49c100d4c"),
     BitVector(hexstring = "4cc5d4becb3e42b6"), BitVector(hexstring = "597f299cfc657e2a"), BitVector(hexstring = "5fcb6fab3ad6faec"), BitVector(hexstring = "6c44198c4a475817")]

###
## Add and return the last 64 bits
###
def add_mod64(lis):
    return BitVector(size = 64, intVal = (sum([int(elem) for elem in lis])) & 0xFFFFFFFFFFFFFFFF)

###
## Generate message schedule
###
def sigma_0(word):
    return (word.deep_copy() >> 1) ^ (word.deep_copy() >> 8) ^ (word.deep_copy().shift_right(7))

def sigma_1(word):
    return (word.deep_copy() >> 19) ^ (word.deep_copy() >> 61) ^ (word.deep_copy().shift_right(6))

def gen_message_schedule(block):
    # Use first block of message for first 16 words
    schedule = [BitVector(size = 64)] * 80
    schedule[0:16] = [block[i:i+WORDSIZE] for i in range(0, 16*WORDSIZE, WORDSIZE)]

    # Calculate rest of message schedule using first 16 words
    for i in range(16, 80):
        schedule[i] = add_mod64([schedule[i - 16], sigma_0(schedule[i - 15]), schedule[i - 7], sigma_1(schedule[i - 2])])
    return schedule


###
## Do round processing for one block of message
###
def ch(e, f, g):
    return (e & f) ^ (~e & g)

def maj(a, b, c):
    return (a & b) ^ (a & c) ^ (b & c)

def sigmaa(a):
    return (a.deep_copy() >> 28) ^ (a.deep_copy() >> 34) ^ (a.deep_copy() >> 39)

def sigmae(e):
    return (e.deep_copy() >> 14) ^ (e.deep_copy() >> 18) ^ (e.deep_copy() >> 41)

def round_processing(message_schedule, buffers):
    # Keep a copy of original buffers
    temp = [buffer for buffer in buffers]
    # Do 80 rounds of processing
    for i, word in enumerate(message_schedule):
        T1 = add_mod64([temp[7], ch(temp[4], temp[5], temp[6]), sigmae(temp[4]), word, K[i]])
        T2 = add_mod64([sigmaa(temp[0]), maj(temp[0], temp[1], temp[2])])
        temp[7] = temp[6]
        temp[6] = temp[5]
        temp[5] = temp[4]
        temp[4] = add_mod64([temp[3], T1])
        temp[3] = temp[2]
        temp[2] = temp[1]
        temp[1] = temp[0]
        temp[0] = add_mod64([T1, T2])

    # Add the output of the 80th round back to original buffers
    for i in range(len(buffers)):
        buffers[i] = add_mod64([buffers[i], temp[i]])


###
## Hash using SHA-512
###
def sha512(infile, outfile):
    # Read and pad message
    with open(infile, "r") as fpin:
        message_bv = BitVector(textstring = fpin.read())
    length = len(message_bv)
    message_bv += BitVector(bitstring = "1")
    message_bv.pad_from_right((BLOCKSIZE - (len(message_bv) % BLOCKSIZE)) - 128)
    message_bv += BitVector(size = 128, intVal = length)
    num_blocks = len(message_bv) // BLOCKSIZE

    # Initialize buffers
    buffers = [BitVector(hexstring="6a09e667f3bcc908"), BitVector(hexstring="bb67ae8584caa73b"),
               BitVector(hexstring="3c6ef372fe94f82b"), BitVector(hexstring="a54ff53a5f1d36f1"),
               BitVector(hexstring="510e527fade682d1"), BitVector(hexstring="9b05688c2b3e6c1f"),
               BitVector(hexstring="1f83d9abfb41bd6b"), BitVector(hexstring="5be0cd19137e2179")]

    # Do round processing for all blocks
    for i in range(num_blocks):
        message_schedule = gen_message_schedule(message_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE])
        round_processing(message_schedule, buffers)

    # Write hash to output file
    with open(outfile, "w") as fpout:
        for buffer in buffers:
            fpout.write(buffer.get_bitvector_in_hex())


if __name__ == "__main__":
    if len(sys.argv) == 3:
        sha512(sys.argv[1], sys.argv[2])
    else:
        sys.exit("Wrong arguments!")