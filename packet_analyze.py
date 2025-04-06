import logging
from scapy.all import sniff, IP, TCP, UDP, ICMP
from colorama import Fore, Style

# Configure logging to save captured packets
logging.basicConfig(filename="captured_packets.log", level=logging.INFO, format="%(asctime)s - %(message)s")

def process_packet(packet):
    """Callback function to process captured packets."""
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = "TCP" if TCP in packet else "UDP" if UDP in packet else "ICMP" if ICMP in packet else "Other"

        # Display colored output for better readability
        print(f"{Fore.CYAN}[+] Packet Captured:{Style.RESET_ALL} {Fore.YELLOW}{src_ip}{Style.RESET_ALL} → {Fore.GREEN}{dst_ip}{Style.RESET_ALL} | Protocol: {Fore.MAGENTA}{protocol}{Style.RESET_ALL}")

        # Save details to log file
        logging.info(f"Source: {src_ip} -> Destination: {dst_ip} | Protocol: {protocol}")

        # Extract payload (first 100 bytes for security)
        if packet.haslayer(TCP) or packet.haslayer(UDP):
            payload = bytes(packet[TCP].payload) if TCP in packet else bytes(packet[UDP].payload)
            if payload:
                print(f"{Fore.LIGHTWHITE_EX}Payload:{Style.RESET_ALL} {payload[:100]}")  # Truncate for safety

# Start sniffing (requires admin/sudo privileges)
print(f"{Fore.GREEN}[*] Starting Packet Capture... (Press Ctrl+C to stop){Style.RESET_ALL}")
sniff(prn=process_packet, store=False)
