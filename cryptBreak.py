#!/usr/bin/env python

### Homework Number: 1
### Name: Elias Talcott
### ECN Login: etalcott
### Due Date: January 23, 2020

import sys
from BitVector import *

###
## Decrypt message given an encrypted file and a bitvector key
###

def cryptBreak(ciphertextFile, key_bv):
    
    # Initialize variables for decryption
    PassPhrase = "Hopes and dreams of a million years"
    BLOCKSIZE = 16
    numbytes = BLOCKSIZE // 8 
    
    # Reduce the passphrase to a bit array of size BLOCKSIZE
    bv_iv = BitVector(bitlist = [0] * BLOCKSIZE)
    for i in range(0, len(PassPhrase) // numbytes):
        textstr = PassPhrase[i * numbytes : (i + 1) * numbytes]
        bv_iv ^= BitVector(textstring = textstr)
        
    # Create a bitvector from the ciphertext hex string
    fpin = open(ciphertextFile)
    encrypted_bv = BitVector(hexstring = fpin.read())
        
    # Create a bitvector for storing the decrypted plaintext bit array
    msg_decrypted_bv = BitVector(size = 0)  
    
    # Carry out differential XORing of bit blocks and decryption
    previous_decrypted_block = bv_iv
    for i in range(0, len(encrypted_bv) // BLOCKSIZE):
        bv = encrypted_bv[i * BLOCKSIZE : (i + 1) * BLOCKSIZE]
        temp = bv.deep_copy()
        bv ^=  previous_decrypted_block
        previous_decrypted_block = temp
        bv ^=  key_bv
        msg_decrypted_bv += bv
   
    return msg_decrypted_bv.get_text_from_bitvector()

###
## Brute force all possible possible key_bv values
###
    
if __name__ == "__main__":
    # Check and separate arguments
    if len(sys.argv) != 2:
        sys.exit("Wrong arguments!")
    _, infile = sys.argv
    
    # Test all 16-bit bitvector keys and check for Mark Twain quote
    for val in range(24000, 2 ** 16):
        key = BitVector(intVal = val, size = 16)
        decryptedMessage = cryptBreak(infile, key)
        if "Mark Twain" in decryptedMessage:
            print("\nKey: {}".format(val))
            print("\n{}".format(decryptedMessage))
            break