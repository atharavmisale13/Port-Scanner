from scapy.all import IP, IPv6, TCP, UDP, DNS, DNSQR, sniff, show_interfaces
from datetime import datetime 
from collections import defaultdict 
import threading 

# Color codes
Red = '\033[91m'
Green = '\033[92m'
Yellow = '\033[93m'
Blue = '\033[94m'
CYAN = '\033[96m'
Reset = '\033[0m'

# Trackers and concurrency locks
syn_count = defaultdict(int)
lock = threading.Lock()

def log_to_file(message):
    with open('scan_log.txt', 'a') as f:
        f.write(f"{message}\n")
        
def check_port_scan(src_ip):
    with lock:
        syn_count[src_ip] += 1
        count = syn_count[src_ip]
        
    # Triggers on 10 and continuously tracks past 10
    if count >= 10:
        if count == 10:
            alert = f"[{datetime.now()}] CRITICAL ALERT: Port Scan detected from {src_ip}!"
            print(f"{Red}{alert}{Reset}")
            log_to_file(alert)
        return True
    return False
    
def packet_callback(packet):
    time_now = datetime.now().strftime("%H:%M:%S")

    # Extract source and destination IPs across IPv4 & IPv6
    if IP in packet:
        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
    elif IPv6 in packet:
        src_ip = packet[IPv6].src
        dst_ip = packet[IPv6].dst
    else:
        return

    # Handle TCP Layer
    if TCP in packet:
        # FIXED: Safe flag conversion handling across all Scapy versions
        flags = packet[TCP].flags
        if (isinstance(flags, int) and flags == 0x02) or "S" in str(flags):
            dst_port = packet[TCP].dport
            is_scan = check_port_scan(src_ip)
            if not is_scan:
                print(f"{Yellow}[{time_now}] SYN{Reset} {src_ip} -> {dst_ip}:{dst_port}")

    # Handle DNS Layer
    elif packet.haslayer(DNS) and packet.haslayer(DNSQR):
        try:
            domain = packet[DNSQR].qname.decode('utf-8')
            print(f"{CYAN}[{time_now}] DNS Request{Reset} {src_ip} asked for: {domain}")
            log_to_file(f"[{datetime.now()}] DNS: {src_ip} -> {domain}")
        except Exception:
            pass

    # Handle UDP Layer
    elif UDP in packet:
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
        print(f"{Blue}[{time_now}] UDP {Reset} {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
 
def main():
    print(f"{Green}" + "-"*60)
    print("Day 7: Smart Packet Sniffer + Port Scan Detector")
    print("Features: SYN Alert, Auto Detect Scans, DNS Log")
    print("Press Ctrl+C to stop. Run as Administrator!")
    print("-"*60 + f"{Reset}") 
    
    print("Available interfaces:")
    show_interfaces()
    iface_name = input("\nEnter interface name from above, or press Enter for auto: ")
    
    with open("scan_log.txt", "w") as f:
        f.write(f"=== Scan Log Started: {datetime.now()} ===\n")
        
    try:
        if iface_name.strip() == "":
            print("Starting sniff on default interface...")
            sniff(prn=packet_callback, store=0)
        else:
            print(f"Starting sniff on {iface_name}...")
            sniff(prn=packet_callback, store=0, iface=iface_name)
            
    except PermissionError:
        print(f"{Red}Error: Run as Administrator! {Reset}")
    except OSError as e:
        print(f"{Red}Error: {e} {Reset}")
        print(f"{Yellow}Tip: Npcap install kar with 'WinPcap API compatible mode' ticked{Reset}")
    except KeyboardInterrupt:
        print(f"\n{Yellow}Sniffer stopped. Check scan_log.txt{Reset}")
        print(f"{CYAN}Total IPs tracked: {len(syn_count)}{Reset}")
       
if __name__ == "__main__":
    main()
