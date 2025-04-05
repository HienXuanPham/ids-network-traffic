from scapy.all import sniff, IP, TCP
from collections import Counter
import threading
import time
import logging
import sys
import signal

logging.basicConfig(filename="network_traffic.log", level=logging.INFO, format="%(message)s")

syn_counter = Counter()
is_attacking = False
stop_sniffing = False

class CheckSYNThread(threading.Thread):
    def run(self):
        global is_attacking, syn_counter
        while not stop_sniffing:
            current_time = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

            if not syn_counter:
                logging.info(f"{current_time} - No traffic detected.")
                print(f"{current_time} - No traffic detected.")
            elif is_attacking:
                ip, count = syn_counter.most_common(1)[0]
                logging.info(f"{current_time} - SYN flood attack detected from {ip} with {count} packets.")
                print(f"{current_time} - SYN flood attack detected from {ip} with {count} packets.")
                is_attacking = False
            else:
                logging.info(f"{current_time} - Normal traffic.")
                print(f"{current_time} - Normal traffic.")
            
            syn_counter.clear()
            time.sleep(2)

def analyze_packet(packet):
    global is_attacking, syn_counter
    
    if packet.haslayer(IP) and packet.haslayer(TCP):
        if packet[TCP].flags and packet[TCP].flags == 2 and packet[TCP].ack == 0:
            src_ip = packet[IP].src
            syn_counter[src_ip] += 1
            if syn_counter[src_ip] > 30:
                is_attacking = True

def signal_handler(sig, frame):
    global stop_sniffing
    stop_sniffing = True
    logging.info("Stopping packet sniffing...")
    sys.exit(0)

signal.signal(signal.SIGINT, signal_handler)

CheckSYNThread().start()

packets = sniff(prn=analyze_packet, store=0)



