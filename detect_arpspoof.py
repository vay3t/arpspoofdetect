#!/usr/bin/env python
import os, time, netifaces, sys, logging
from scapy.all import sniff

# Number of ARP replies received from a specific mac before flagging it
request_threshold = 10

# The script requires root to run. Check if user is root
if os.geteuid() != 0:
	exit("Root permisson is required to operate on network interfaces. \nNow Aborting.")

# If none specified, set to default
filename = "spoof.log"

# Set logging structure
logging.basicConfig(format='%(levelname)s: %(asctime)s %(message)s', datefmt='%m/%d/%Y %I:%M:%S %p', filename=filename, filemode="a", level=logging.DEBUG)
# Read available network interfaces
available_interfaces = netifaces.interfaces()
# Ask user for desired interface
interface = sys.argv[1]
# Check if specified interface is valid
if not interface in available_interfaces:
    exit("Interface {} not available.".format(interface))
# Retrieve network addresses (IP, broadcast) from the network interfaces
addrs = netifaces.ifaddresses(interface)
try:
    local_ip = addrs[netifaces.AF_INET][0]["addr"]
    broadcast = addrs[netifaces.AF_INET][0]["broadcast"]
except KeyError:
    exit("Cannot read address/broadcast address on interface {}".format(interface))

requests = []
replies_count = {}
notification_issued = []

logging.info("ARP Spoofing Detection Started on {}".format(local_ip))

def check_spoof(source, mac, destination):
    # Function checks if a specific ARP reply is part of an ARP spoof attack or not
    if destination == broadcast:
        if not mac in replies_count:
            replies_count[mac] = 0

    if not source in requests and source != local_ip:
        if not mac in replies_count:
            replies_count[mac] = 0
        else:
            replies_count[mac] += 1
        # Logs ARP Reply
        logging.warning("ARP replies detected from MAC {}. Request count {}".format(mac, replies_count[mac]))

        if (replies_count[mac] > request_threshold) and (not mac in notification_issued):
            # Check number of replies reaches threshold or not, and whether or not we have sent a notification for this MAC addr
            logging.error("ARP Spoofing Detected from MAC Address {}".format(mac)) # Logs the attack in the log file
            # Issue OS Notification
            print("[!] ARP Spoofing Detected -> {}".format(mac))
            # Add to sent list to prevent repeated notifications.
            notification_issued.append(mac)
    else:
        if source in requests:
            requests.remove(source)

def packet_filter (packet):
    # Retrieve necessary parameters from packet
    source = packet.sprintf("%ARP.psrc%")
    dest = packet.sprintf("%ARP.pdst%")
    source_mac = packet.sprintf("%ARP.hwsrc%")
    operation = packet.sprintf("%ARP.op%")
    if source == local_ip:
        requests.append(dest)
    if operation == 'is-at':
        return check_spoof(source, source_mac, dest)

print("[+] ARP Spoofing Detection Started...")
# Rely on scapy sniff function to do the hard job - sniffing packets.
sniff(filter = "arp", prn = packet_filter, store = 0)
