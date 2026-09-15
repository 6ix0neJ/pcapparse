from scapy.all import PcapReader
from pathlib import Path
import ipaddress
import threading
import pyshark
import time
import os

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
url = "https://github.com/6ix0neJ"
print("Written By Jibril Richardson (6ix0neJ on Github) - ", url)
print("Packet Parser v1.0")

pcap_files_found = []

localorspecific = input("Search for pcap file in current directory or specify path? (c/s): ")

if localorspecific  == "c":
    print("Searching for pcap file recursively in the current directory...")
    directory = Path('.')
    # Find all .pcapng and .pcap files recursively
    pcap_files_found = list(directory.rglob('*.pcapng')) + list(directory.rglob('*.pcap'))
    print("Found ", len(pcap_files_found), " pcap files.")
    if len(pcap_files_found) == 0:
        print("No pcap files found in the current directory.")
        print("exiting...")
        exit()
    print("Which should be used? (0 -", len(pcap_files_found) - 1, ")")
    for i, pcap_file in enumerate(pcap_files_found):
        print(f"{i}: {pcap_file}")
    selected_index = int(input("Enter the index of the pcap file to use: "))
    if 0 <= selected_index < len(pcap_files_found):
        pcapf = pcap_files_found[selected_index]
    else:
        print("Invalid index selected. Exiting.")
        exit()
    pcapf = os.path.basename(pcapf)

elif localorspecific == "s":
    pcapf = input("Pcap path: ")
    pcapf = os.path.basename(pcapf)

if not pcap_files_found:
    print("No pcap files found.")
    exit()


def live_timer(stop_event):
    """Worker function for the background timer."""
    live_start_time = time.time()

    # Run until the main process sets the stop_event
    while not stop_event.is_set():
        elapsed = int(time.time() - live_start_time)
        mins, secs = divmod(elapsed, 60)

        print(f"\rElapsed Time: {mins:02d}:{secs:02d}", end="", flush=True)
        time.sleep(1)

#pcapf = pcap_files_found[0]  # Use the first found pcap file
print("Parsing", pcapf,"...")

#print(type(pcapf))

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

def isprotocol(pcapf, protocol):
    # This function is DEFINITELY not ready it barely even works I lowkey just moved one to other things but ill be back to fic it 100%
    try:
        cap = pyshark.FileCapture(pcapf, display_filter=protocol)
        packets = [packet for packet in cap]
        cap.close()
        return packets
    except Exception as e:
        print(f"Error reading pcap file: {e}")
        return []

with PcapReader(pcapf) as pcap_reader:
    try:

        start_time = time.perf_counter()

        stop_live_timer = threading.Event()

        live_timer_thread = threading.Thread(target=live_timer, args=(stop_live_timer,), daemon=True)
        live_timer_thread.start()

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

            #if isprotocol(pcapf, "tcp"):
            #    protocols.append("TCP")

        stop_time = time.perf_counter()

    finally: 
        stop_live_timer.set()
        live_timer_thread.join()


elapsed_time = stop_time - start_time
print("\n")
print("pcap analysis completed in", int(elapsed_time), "seconds.")

print("Valid IPs found in the pcap file:", len(src_ips) + len(dst_ips))
print("Protocols found:", len(protocols))
showips = input("List valid Ips? (y/n): ")
if showips == "y": iplist()

print(protocols)

print("Exiting...")