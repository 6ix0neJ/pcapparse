from scapy.all import PcapReader
from pathlib import Path
import ipaddress
import time

def bannershow():
    print("████   ███   ███  ████     ████   ███  ████   ████ █████  ")
    print("█░░░█ █ ░░░ █ ░░█ █░░░█    █░░░█ █ ░░█ █░░░█ █ ░░░░█░░░░░ ")
    print("████░░█░ ░░░█████░████░░   ████░░█████░████░░ ███░░████░░░ ")
    print("█░░░░ █░░   █░░░█░█░░░░ ░  █░░░░ █░░░█░█░░█░ ░ ░░█ █░░░░   ")
    print("█░░░░░ ███  █░░░█░█░░░░░   █░░░░░█░░░█░█░░░█░████░░█████░  ")
    print(" ░░     ░░░  ░░  ░░░░       ░░    ░░  ░░░░  ░ ░░░░ ░░░░░░  ")
    print("  ░      ░░░  ░   ░ ░        ░     ░   ░ ░   ░ ░░░░  ░░░░░ ")
    print(" ")

bannershow()
print("Packet Parser v1.0")
pcapf = " "
localorspecific = input("Search for pcap file in current directory or specify path? (c/s): ")
if localorspecific == "s":
    pcapf = input("Pcap path: ")
elif localorspecific  == "c":
    print("Searching for pcap file recursively in the current directory...")
    directory = Path('.')
    # Find all .pcapng and .pcap files recursively
    pcap_files = list(directory.rglob('*.pcapng')) + list(directory.rglob('*.pcap'))
    print("Found ", len(pcap_files), " pcap files.")
    print("Which should be used? (0 -", len(pcap_files)-1, ")")
    for i, pcap_file in enumerate(pcap_files):
        print(f"{i}: {pcap_file}")
    selected_index = int(input("Enter the index of the pcap file to use: "))
    if 0 <= selected_index < len(pcap_files):
        pcapf = pcap_files[selected_index]
    else:
        print("Invalid index selected. Exiting.")
        exit()

if not pcap_files:
    print("No pcap files found.")
    exit()

#pcapf = pcap_files[0]  # Use the first found pcap file

validips = []
src_ips = []
dst_ips = []

protocols = []

def is_valid_ip(ip_str):
    try:
        ipaddress.ip_address(ip_str)
        return True
    except ValueError:
        return False
def iplist():
    print(f"{'Source IPs':<17} {'Destination IPs':<10}")
    print("-" * 36)

    for src_ip, dst_ip in zip(src_ips, dst_ips):
        print(f"{src_ip:<17} {dst_ip:<10}")

def isprotocol(packet):
    if packet.haslayer("ARP"):
        protocols.append("ARP found")
    if packet.haslayer("DNS"):
        protocols.append("DNS found")
    if packet.haslayer("TCP"):
        protocols.append("TCP found")
    if packet.haslayer("UDP"):
        protocols.append("UDP found")
    if packet.haslayer("ICMP"):
        protocols.append("ICMP found")

with PcapReader(pcapf) as pcap_reader:
    start_time = time.perf_counter()
    for packet in pcap_reader:
        # isprotocol(packet)
        if packet.haslayer("IP"):
            src_ip = packet["IP"].src
            dst_ip = packet["IP"].dst

            if is_valid_ip(src_ip) and is_valid_ip(dst_ip):

                    if src_ip not in validips:
                        src_ips.append(src_ip)
                        validips.append(src_ip)
                    if dst_ip not in validips:
                        dst_ips.append(dst_ip)
                        validips.append(dst_ip)
    stop_time = time.perf_counter()


eleapsed_time = stop_time - start_time
print("pcap analysis completed in ", eleapsed_time)

print("Valid IPs found in the pcap file:", len(validips))
print("Protocols found:", len(protocols))
showips = input("List valid Ips? (y/n): ")
if showips == "y": iplist()

print(protocols)

print("Exiting...")