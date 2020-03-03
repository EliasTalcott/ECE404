#!/usr/bin/env python3

# Homework Number: 6
# Name: Elias Talcott
# ECN Login: etalcott
# Due Date: March 3, 2020

from BitVector import *
import rsa
import sys
import numpy as np

###
## Call syntax:
## python3 breakRSA.py -e message.txt enc1.txt enc2.txt enc3.txt n_1_2_3.txt #Steps 1 and 2
## python3 breakRSA.py -c enc1.txt enc2.txt enc3.txt n_1_2_3.txt cracked.txt #Step 3
###

BLOCKSIZE = 128

###
## Calculate pth root of x
###
# def solve_pRoot(p,y):
#     p = int(p)
#     y = int(y)
#     # Initial guess for xk
#     try:
#         xk = int(pow(y,1.0/p))
#     except:
#         # Necessary for larger value of y
#         # Approximate y as 2^a * y0
#         y0 = y
#         a = 0
#         while (y0 > sys.float_info.max):
#             y0 = y0 >> 1
#             a += 1
#         # log xk = log2 y / p
#         # log xk = (a + log2 y0) / p
#         xk = int(pow(2.0, ( a + np.log2(float(y0)) )/ p ))
#
#     # Solve for x using Newton's Method
#     err_k = int(pow(xk,p))-y
#     while (abs(err_k) > 1):
#         gk = p*int(pow(xk,p-1))
#         err_k = int(pow(xk,p))-y
#         xk = int(-err_k/gk) + xk
#     return xk


def solve_pRoot(p, x): #O(lgn) solution
	#Upper bound u is set to as follows:
	#We start with the 2**0 and keep increasing the power so that u is 2**1, 2**2, ...
	#Until we hit a u such that u**p is > x
	u = 1
	while u ** p <= x: u *= 2

	#Lower bound set to half of upper bound
	l = u // 2

	#Keep the search going until upper u becomes less than lower l
	while l < u:
		mid = (l + u) // 2
		mid_pth = mid ** p
		if l < mid and mid_pth < x:
			l = mid
		elif u > mid and mid_pth > x:
			u = mid
		else:
			# Found perfect pth root.
			return mid
	return mid + 1


###
## Find multiplicative inverse
###
def MI(num, mod):
    NUM = num; MOD = mod
    x, x_old = 0, 1
    y, y_old = 1, 0
    while mod:
        q = num // mod
        num, mod = mod, num % mod
        x, x_old = x_old - q * x, x
        y, y_old = y_old - q * y, y
    return (x_old + MOD) % MOD

###
## Chinese Remainder Theorem
###
def crt(a_list, m_list):
    # Calculate product of moduli
    m = 1
    for elem in m_list:
        m *= elem

    # Calculate c values
    c_list = [0] * len(m_list)
    for i, elem in enumerate(m_list):
        mi = m // elem
        mi_inv = MI(mi, elem)
        c_list[i] = mi * mi_inv

    # Calculate A
    a = 0
    for i, elem in enumerate(a_list):
        a += elem * c_list[i]
    return a % m


###
## Encrypt a message 3 times
###
def encrypt(infile, outfiles, keyfile):
    # Convert message to bitvector
    with open(infile) as fpin:
        message_bv = BitVector(textstring = fpin.read())

    # Generate sets of keys and write encrypted versions of the message
    e = 3
    ps_and_qs = [(None, None)] * len(outfiles)
    for i, outfile in enumerate(outfiles):
        ps_and_qs[i] = rsa.gen_keys(e)
        with open(outfile, "w") as fpout:
            fpout.write(rsa.encrypt(message_bv, ps_and_qs[i][0], ps_and_qs[i][1], e))

    # Write public keys to keyfile
    ns = [str(p * q) for (p, q) in ps_and_qs]
    with open(keyfile, "w") as fpkey:
        fpkey.write("\n".join(ns))


###
## Crack RSA using three separately encrypted messages
###
def crack(encfiles, keyfile, outfile):
    # Read encrypted files into integers
    enc_messages = [0] * 3
    for i, encfile in enumerate(encfiles):
        with open(encfile) as fpin:
            enc_messages[i] = int(BitVector(hexstring = fpin.read()))

    # Read public keys
    with open(keyfile) as fpkey:
        keys = [int(elem) for elem in fpkey.read().splitlines()]

    # Crack RSA with CRT
    a_cubed = crt(enc_messages, keys)
    a = solve_pRoot(3, a_cubed)
    result = BitVector(intVal = a).get_text_from_bitvector()

    # Write cracked message to outfile
    print("{:e}".format(a_cubed))
    print("{:e}".format(a))
    print(result)
    with open(outfile, "w") as fpout:
        fpout.write(result)


if __name__ == "__main__":
    if len(sys.argv) == 7 and sys.argv[1] == "-e":
        encrypt(sys.argv[2], [sys.argv[3], sys.argv[4], sys.argv[5]], sys.argv[6])
    elif len(sys.argv) == 7 and sys.argv[1] == "-c":
        crack([sys.argv[2], sys.argv[3], sys.argv[4]], sys.argv[5], sys.argv[6])
    else:
        sys.exit("Wrong arguments!")