#!/usr/bin/env python 3

from TcpAttack import *

# Set values
spoofIP = "192.168.1.50"
targetIP = "192.168.1.1"
rangeStart = 0
rangeEnd = 1000

# Test TcpAttack class
Tcp = TcpAttack(spoofIP, targetIP)
#Tcp.scanTarget(rangeStart, rangeEnd)
if Tcp.attackTarget(53, 1000):
    print("port was open to attack")