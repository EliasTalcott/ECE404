#!/usr/bin/env python 3

from TcpAttack import *

# Set values
spoofIP = "192.168.1.1"
targetIP = "192.168.1.1"
rangeStart = 50
rangeEnd = 100

# Test TcpAttack class
Tcp = TcpAttack(spoofIP, targetIP)
Tcp.scanTarget(rangeStart, rangeEnd)
if Tcp.attackTarget(22, 10):
    print("port was open to attack")