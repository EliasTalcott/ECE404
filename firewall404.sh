#!/usr/bin/env bash

# Clear any existing rules or chains
sudo iptables -t filter -F
sudo iptables -t filter -X
sudo iptables -t mangle -F
sudo iptables -t mangle -X
sudo iptables -t nat -F
sudo iptables -t nat -X
sudo iptables -t raw -F
sudo iptables -t raw -X

# Change source IP address for all outgoing packets to my machine's address
sudo iptables -t nat -A POSTROUTING -o enp0s3 -j MASQUERADE

# Block 3 specific IP addresses for incoming connections
sudo iptables -A INPUT -s facebook.com -j DROP
sudo iptables -A INPUT -s amazon.com -j DROP
sudo iptables -A INPUT -s twitter.com -j DROP

# Block pings from all other hosts
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Forward packets from port 4269 to port 22 (SSH)
MYIP=$(hostname -I | cut -d" " -f1)
sudo iptables -t nat -A PREROUTING -p tcp --dport 4269 -j DNAT --to-destination ${MYIP}:22

# Allow SSH access from only the engineering.purdue.edu domain
sudo iptables -A INPUT -p tcp ! -s engineering.purdue.edu --dport 22 -j DROP

# Only allow a single IP access to access my machine for the HTTP service
sudo iptables -A INPUT -p tcp ! -s 192.168.1.9 --dport 80 -j DROP
sudo iptables -A OUTPUT -p tcp ! -s 192.168.1.9 --dport 80 -j DROP

# Permit Auth/Ident (port 113)
sudo iptables -A INPUT -p tcp --dport 113 -j ACCEPT
sudo iptables -A OUTPUT -p tcp --sport 113 -j ACCEPT
