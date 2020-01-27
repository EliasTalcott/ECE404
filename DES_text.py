#!/usr/bin/env python

# Homework Number: 2
# Name: Elias Talcott
# ECN Login: etalcott
# Due Date: January 30, 2020

import sys
from BitVector import *


###
## Encryption algorithm
###
def encrypt(infile, key, outfile):
    print("Encrypt")    
 
    
###
## Decryption algorithm
###
def decrypt(infile, key, outfile):
    print("Decrypt")


###
## Check arguments and choose encrypt or decrypt option
###
if len(sys.argv) != 5:
    sys.exit("Wrong arguments!")
    
if sys.argv[1] == "-e":
    encrypt(sys.argv[2], sys.argv[3], sys.argv[4])
elif sys.argv[1] == "-d":
    decrypt(sys.argv[2], sys.argv[3], sys.argv[4])
else:
    sys.exit("Wrong arguments!")