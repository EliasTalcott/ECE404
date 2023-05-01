import cryptBreak
from BitVector import *

key = 25202
key_bv = BitVector(intVal = key, size = 16)
decryptedMessage = cryptBreak.cryptBreak("encrypted.txt", key_bv)

if "Mark Twain" in decryptedMessage:
    print("\n{}".format(decryptedMessage))
else:
    print("\n{}".format(decryptedMessage))
    print("Wrong decryption key")