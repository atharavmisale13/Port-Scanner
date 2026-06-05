import socket
import sys 
import time 
from datetime import datetime 

target=input("Enter your IP adress: ")

print("-" * 50)
print(f"Scanning Target: {target}")
print(f"Time Started: {datetime.now()}")
print("-" * 50)

open_ports=[] 

start=1 
end=1024 
total_ports=end -start + 1
t1=datetime.now() 


print(f"Scanning {target} from port {start} to {end}") 

for i,port in enumerate(range(start,end+1)) :
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
        sock.settimeout(0.5)
        result=sock.connect_ex((target,port))
        
        progress=(i + 1) / total_ports*100 
        bar_length=30 
        filled=int(bar_length * (i+1) // total_ports)
        bar='#' * filled + '-' * (bar_length - filled)
        
        print(f'\r[{bar}] {progress:.1f}% Port: {port}', end='')
        
        if result==0:
             print(f'\nPort {port}: Open') 
             open_ports.append(port) 
             
        sock.close() 
        
    except KeyboardInterrupt:
        print("\nScan stopped by user")
        sys.exit()
    except socket.gaierror:
        print("\nHostname could not be resolved")
        sys.exit()
    except socket.error:
        print("\nCouldn't connect to server")
        sys.exit()        

t2=datetime.now()
total_time=t2-t1


print("\n\n" + "-" * 50)
print("Scan Complete!")
print(f"Total open ports found: {len(open_ports)}")
print(f"Open ports: {open_ports}")
print(f"Time taken: {total_time}")
print("-" * 50)