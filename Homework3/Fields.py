#!/usr/bin/env python3

# Homework Number: 3
# Name: Elias Talcott
# ECN Login: etalcott
# Due Date: February 6, 2020

# Input integer n
n = "-1"
while not n.isdigit() or eval(n) < 1:
    n = input("Enter a positive integer: ")
    if not n.isdigit() or eval(n) < 1:
        print("{} is not a positive integer.".format(n))
n = eval(n)

# Check if n is prime
if n < 2:
    prime = False
elif n == 2:
    prime = True
elif n > 2:
    prime = True
    for i in range(2, n // 2):
        if n % i == 0:
            prime = False
            break
            
# If n is prime, then Zn is a finite field, else it is a ring
if prime:
    print("field")
else:
    print("ring")