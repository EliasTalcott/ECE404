#!/usr/bin/env python3

# Homework Number: 8
# Name: Elias Talcott
# ECN Login: etalcott
# Due Date: March 26, 2020

from scapy.all import *

class TcpAttack:
    def __init__(self, spoofIP, targetIP):
        self.spoofIP = spoofIP
        self.targetIP = targetIP

    def scanTarget(self, rangeStart, rangeEnd):
        openports = []
        for port in range(rangeStart, rangeEnd + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if sock.connect_ex((self.targetIP, port)) == 0:
                print("Open: {}".format(port))
                openports.append(port)
            else:
                print("Closed: {}".format(port))
            sock.close()

        # Print open ports to a text file
        if openports:
            with open("openports.txt", "w") as fpout:
                fpout.writelines(str(port) + "\n" for port in openports[:-1])
                fpout.writelines(str(openports[-1]))


    def attackTarget(self, port, numSyn):
        pass