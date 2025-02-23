import scapy.all as scapy
import time
import msvcrt  

def packet_callback(packet):
    try:
        # Check for IP layer
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst
            print(f"\n[*] IP Packet: {ip_src} -> {ip_dst}")

        # Check for TCP layer
        if packet.haslayer(scapy.TCP):
            tcp_sport = packet[scapy.TCP].sport
            tcp_dport = packet[scapy.TCP].dport
            print(f"    TCP Port: {tcp_sport} -> {tcp_dport}")
            print(f"    Flags: {packet[scapy.TCP].flags}")

        # Check for UDP layer
        elif packet.haslayer(scapy.UDP):
            udp_sport = packet[scapy.UDP].sport
            udp_dport = packet[scapy.UDP].dport
            print(f"    UDP Port: {udp_sport} -> {udp_dport}")

        # Check for raw payload
        if packet.haslayer(scapy.Raw):
            raw_data = packet[scapy.Raw].load
            print(f"    Raw Data (first 100 bytes): {raw_data[:100]}\n")

    except Exception as e:
        print(f"Error: {e}")

print("[*] Starting network sniffer...")
print("[*] Press 'Q' to quit...")

# Start sniffing in a separate thread
sniff_thread = scapy.AsyncSniffer(prn=packet_callback, store=False)
sniff_thread.start()

# Keep the script running and check for 'Q' key press
while True:
    if msvcrt.kbhit():
        if msvcrt.getch().decode().lower() == 'q':
            break
    time.sleep(0.1)

print("\n[*] Stopping sniffer...")
sniff_thread.stop()

print("[*] Press Enter to exit...")
input()