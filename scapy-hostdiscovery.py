#!/usr/bin/env python

from scapy.all import *

# Prompt the user for the network range to scan
network = input("Enter the network range to scan (e.g. 192.168.1.0/24): ")

# Prompt the user for the timeout value for responses
timeout = input("Enter the timeout value for responses (in seconds): ")

# Convert the timeout value to an integer
timeout = int(timeout)

# Send an ARP request for each IP in the network range
# and save the responses in a list
responses, _ = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network),
                  timeout=timeout)

# Extract the responded IPs from the list of responses
responded_ips = [r[1].psrc for r in responses]

# Send an ICMP request for each IP in the network range
# and save the responses in a list
responses, _ = srp(IP(dst=network)/ICMP(), timeout=timeout)

# Extract the responded IPs from the list of responses
responded_ips += [r[1].src for r in responses]

# Remove any duplicate IPs
responded_ips = list(set(responded_ips))

# Print the responded IPs
print("Responded IPs:")
for ip in responded_ips:
    print(ip)