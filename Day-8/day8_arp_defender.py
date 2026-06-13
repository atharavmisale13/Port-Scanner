from scapy.all import ARP, sniff, conf
from datetime import datetime
import threading
import time 

Red='\033[91m'
Green='\033[92m'
Yellow='\033[93m'
Blue='\033[94m'
Cyan='\033[96m'
Reset='\033[0m'

arp_table={}
lock=threading.Lock()
gateway_ip=None 

def log_alert(message):
    timestamp=datetime.now().strftime("%Y-%m-%d%H:%M:%S")
    with open('arp_alert.txt','a') as f:
        f.write(f"[{timestamp}]{message}\n")
    print(f"{Red}{message}{Reset}")    
    
def get_gateway():
    global gateway_ip
    try:
        gateway_ip=conf.route.route("0.0.0.0")[2]
        print(f"{Green}[+] Gateway Detected: {gateway_ip}{Reset}")    
    except:
        print(f"{Yellow}[!] Gateway auto-detect fail.Manual daal{Reset}")    
        
        gateway_ip=input("Enter Gateway IP (e.g. 192.168.1.1):")

def arp_callback(packet):
    if packet.haslayer(ARP) and packet[ARP].op==2:
       
       src_ip=packet[ARP].psrc 
       src_mac=packet[ARP].hwsrc 
       
       with lock:
           if src_ip not in arp_table:
               arp_table[src_ip]=src_mac
               print(f"{Blue}[+] New Host: {src_ip} -> {src_mac}{Reset}")   
            
            
           elif arp_table[src_ip]!=src_mac:
               old_mac=arp_table[src_ip]        
               
               if src_ip == gateway_ip:
                   alert=f"CRITICAL: Gateway {src_ip} MAC changed! {old_mac} -> {src_mac} | Possible MITM Attack"
                   log_alert(alert)
                   
                   
               else:
                   alert =f"WARINING: IP {src_ip} MAC changed! {old_mac} -> {src_mac} | Possible ARP Spoof!"
                   log_alert(alert) 
                   
                   arp_table[src_ip] = src_mac
                   
                   
def main():
    print(f"{Green}" + "-"*60)
    print("Day 8: ARP Spoof Detector") 
    print("Features: Real-time MITM Detection, Gateway Protection")
    print("Press Ctrl+C to stop. Run as Administrator!")  
    print("-"*60 + f"{Reset}")    
    
    get_gateway()              
    
    print(f"{Cyan}[*] Starting ARP Monitor...Press Ctrl+C to stop{Reset}")
    log_alert("===ARP Monitor Started ===")
    
    try:
        sniff(filter="arp",prn=arp_callback,store=0)
        
    except PermissionError:
        print(f"{Red} Error:Run as Administrator! {Reset}")
        
    except KeyboardInterrupt:
        print(f"\n{Yellow}[*] Detector stopped.Check arp_alert.txt{Reset}")
        
        print(f"{Cyan} Total host tracked: {len(arp_table)}{Reset}")
        
if __name__ == "__main__"   :
    main()             