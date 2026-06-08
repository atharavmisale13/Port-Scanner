from scapy.all import sniff, IP, TCP,  UDP, ICMP 
from datetime import datetime  

Red='\033[91m' 
Green='\033[92m'
Yellow='\033[93m'
Blue='\033[94m'
Reset='\033[0m'

def packet_callback(packet):
    time =datetime.now().strftime("%H:%M:%S")
    
    if IP in packet:
        src_ip=packet[IP].src 
        dst_ip=packet[IP].dst 
        
        if TCP in packet :
            src_port =packet[TCP].sport 
            dst_port = packet[TCP].dport 
            flags=packet[TCP].flags 
            
            
            if flags == "S":
                print(f"{Red}[{time}] Alert:SYN Scan Detected!{Reset}")
                print(f"{Yellow}From: {src_ip}:{src_port} -> To: {dst_ip}:{dst_port}{Reset}")
                print(f"{Blue} Possible Nmap Scan! {Reset}\n")
            else:
                print(f"{Green}[{time}] TCP{Reset} {src_ip}:{src_port} -> {dst_ip}:{dst_port} Flags:{flags}") 
                
                
        elif UDP in packet:
            src_port = packet[UDP].sport  
            dst_port=packet[UDP].dport    
            print(f"{Blue}[{time}] UDP {Reset} {src_ip}:{src_port} -> {dst_ip} : {dst_port}") 
            
        elif ICMP in packet:
            print(f"{Yellow}[{time}] ICMP Ping {Reset} {src_ip} -> {dst_ip}")


def main():
    print(f"{Green}" + "-" * 60)
    print("Day-6:Network Packet Sniffer Started")
    print("Press Ctrl+C to stop")
    print("Run as Administrator or it won't work!")
    print("-" * 60 + f"{Reset}")     
    
    
    try:
        
        sniff(prn=packet_callback,store=0)
    except PermissionError:
        print(f"{Red} Error:Run this scripts as Adminstrator! {Reset}")
    except KeyboardInterrupt:
        print(f"\n{Yellow} Sniffer stopped by user.{Reset}")
        
        
if __name__ == "__main__":
    main()        
                                