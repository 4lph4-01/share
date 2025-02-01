#!/bin/bash
# Description: Performs a network scan using nmap

NETWORK_RANGE="192.168.1.0/24"

# Perform network scan
nmap -sP $NETWORK_RANGE

# Output results
nmap -oN scan_results.txt $NETWORK_RANGE

