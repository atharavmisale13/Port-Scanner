import socket 
import sys 
import threading
import argparse 
from datetime import datetime 
from queue import Queue 

Green='\033[92m'
Red='\033[91'
Yellow='\033[93m'
Blue='\033[94m'
Reset='033[0m'

print_lock=threading.Lock()
port_queue=Queue()
open_ports=[]
scan_results=[]

common_ports = {
    21:'FTP',22:'SSH',23:'Telnet',25:'SMTP',
    53:'DNS',80:'HTTP',110:'POP3',143:'IMAP',
    443:'HTTPS',3306:'MySQL',3389:'RDP',8080:'HTTP-Proxy'
}

def scan_port(target,port):
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(1)
        result=sock.connect_ex((target,port))
        
        if result == 0:
            service = common_ports.get(port,"Unknown")
            try: 
                sock.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner=sock.recv(1024).decode().strip().split('\n')[0]
                
            except:
                banner="No banner"
                
            output =f"Port {port} : {Green}Open{Reset} - {Blue}{service}{Reset} - {Yellow}{banner}{Reset}"
            file_output=f"Port {port}: Open - {service} - {banner}"
            
            
            with print_lock:
                print(output)
                open_ports.append(port)
                scan_results.append(file_output)
                
            sock.close()
            
    except socket.timeout:
        pass
    except Exception as e:
        pass
    
def threader(target):
    while True:
        port=port_queue.get()
        scan_port(target,port)
        port_queue.task_done()
        
def save_to_file(target,start_port,end_port,total_time):
    filename=f"scan_{target.replace(".","_")}_{datetime.now().strftime("%Y%m%d_%H%M%S")}.txt"
    with open(filename,'w') as f:
        f.write(f"Scan Report for {target}\n")
        f.write(f"Date : {datetime.now()}\n")
        f.write(f"Port Range: {start_port}-{end_port}\n")
        f.write(f"Time Taken: {total_time}\n")
        f.write("-" * 60 + "\n")
        f.write(f"Total Open Port: {len(open_ports)}\n\n")
        for result in sorted(scan_results,key=lambda x: int(x.split()[1][:-1])):
            f.write(result + "\n")
        return filename
    
    
def main():
    parser =argparse.ArgumentParser(description="Pro Port Scanner - Day 5 ")
    parser.add_argument("-t","--target", required=True,help="Target IP or Domain")
    parser.add_argument("-p", "--ports", default="1-1024", help="Port range: 1-1024 or 80,443")
    parser.add_argument("-th","--threads",type=int,default=100,help="Number of threads")
    parser.add_argument("-o","--output",action="store_true",help="Save result to file")
    
    args=parser.parse_args()
    target = args.target 
    threads=args.threads  
    
    if "," in args.ports:
        ports_list=[int(p.strip()) for p in args.ports.split(',')]
        start_port,end_port=min(ports_list),max(ports_list)  
        
    elif "-" in args.ports:
        start_port,end_port=map(int,args.ports.split('-'))
    else:
        start_port =end_port=int(args.ports) 
        
    
    print(f"{Blue}" + "-" * 60)
    print(f"Scanning Target: {target}")
    print(f"Port Range: {start_port}-{end_port}")    
    print(f"Threads:{threads}")     
    print(f"Time Started: {datetime.now()}")
    print("-" * 60 + f"{Reset}") 
    
    t1=datetime.now()
    
    try:
        
        for _ in range(threads):
            t=threading.Thread(target=threader,args=(target,))
            t.daemon=True  
            t.start()
            
        if "," in args.ports:
            for port in ports_list:
                port_queue.put(port)
                
        else:
            for port in range(start_port,end_port +1):
               port_queue.put(port)
               
        port_queue.join()
        
        
        
    except KeyboardInterrupt:
        print(f"\n{Red}Scan stopped by user.Exiting...{Reset}")
        sys.exit()
        
    t2=datetime.now()
    total_time=t2 -t1 
    
    print(f"\n{Blue}" + "-" * 60)
    print(f"{Green} Scan Complete! {Reset}")
    print(f"Total open ports found: {len(open_ports)}")
    print(f"Open ports: {sorted(open_ports)}")      
    print(f"Time taken: {total_time}")
    print("-" * 60 + f"{Reset}")
    
    if args.output:
        filename=save_to_file(target,start_port,end_port,total_time)
        print(f"{Yellow}Result saved to: {filename}{Reset}")
        
if __name__ == "__main__":
    main()                            