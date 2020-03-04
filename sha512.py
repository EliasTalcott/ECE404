#!/usr/bin/env python3

# Homework Number: 7
# Name: Elias Talcott
# ECN Login: etalcott
# Due Date: March 12, 2020

import hashlib
import sys

###
## Call syntax: python3 sha512.py input.txt hash.txt
###

###
## Hash using SHA-512
###
def sha512(infile):
    pass

if __name__ == "__main__":
    if len(sys.argv) == 3:
        sha512(sys.argv[1], sys.argv[2])
    else:
        sys.exit("Wrong arguments!")