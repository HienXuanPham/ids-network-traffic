from scapy.all import sniff, wrpcap

def sniff_packets(packet):
    print(packet.summary())

packets = sniff(prn=sniff_packets, iface="Wi-Fi", count=100)
wrpcap("network_traffic.pcap", packets)



