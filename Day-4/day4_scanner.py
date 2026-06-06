import socket 
import sys 
import threading 
import argparse 
from datetime import datetime 
from queue import Queue 

print_lock=threading.Lock() 

port_queue=Queue() 
open_ports=[] 

def scan_port(target,port):
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(1)
        result=sock.connect_ex((target,port))
        
        if result ==0:
            try: 
                sock.send(b'GET / HTTP/1.1\r\n\r\n')
                banner =sock.recv(1024).decode().strip()
                banner=banner.split('\n')[0]
            except :
                banner ="No banner"
                
            with print_lock:
                print(f"Port {port}: Open - {banner}")
                open_ports.append(port)   
                
        sock.close()
    except :
        pass

def threader(target):
    port=port_queue.get()
    scan_port(target,port)
    port_queue.task_done()    
    
def main():
        parser=argparse.ArgumentParser(description="Fast Port Scanner - Day 4")
        parser.add_argument("-t","--target",required=True,help="Target IP or domain")
        parser.add_argument("-p","--ports",default="1-1024",help="Port range: 1-1024")
        parser.add_argument("-th","--threads",type=int,default=100,help="Number of threads")
        
        args=parser.parse_args()
        
        target=args.target
        threads=args.threads 
        
        if '-' in args.ports: 
            start_port,end_port =map(int,args.ports.split('-'))
        else:
            start_port=end_port=int(args.ports)
            
        print("-" * 60)
        print(f"Scanning Target : {target}")
        print(f"Port Range: {start_port} -{end_port}") 
        print(f"Threads: {threads}")  
        print(f"Time Started : {datetime.now()}")
        print("-" * 60)
        
        t1=datetime.now()
        
        for _ in range(threads):
            t=threading.Thread(target=threader,args=(target,))  
            t.daemon=True 
            t.start()
            
        for port in range(start_port,end_port + 1):
            port_queue.put(port)
            
        port_queue.join()
        
        t2=datetime.now()
        total_time=t2-t1 
        
        print("\n" + "-" * 60)
        print("Scan Complete!") 
        print(f"Total open ports found: {len(open_ports)}") 
        print(f"Open ports: {sorted(open_ports)}")
        print(f"Time taken: {total_time}")         
        print("-" * 60)
        
if __name__ == "__main__":
     main()
     