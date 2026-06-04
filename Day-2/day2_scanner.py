import socket
import sys
import time

if len(sys.argv)!=2:
    print("Usage: python3 day1_scanner.py <target>")
    sys.exit()
    
    
target=sys.argv[1]
print(f"Scanning {target} ports 1-100...")
start=time.time()

try:
    
  for port in range(1,101):
    s=socket.socket()
    s.settimeout(0.5)
    result = s.connect_ex((target, port))
    
    if result==0:
       print(f"Port {port} is Open")
    s.close()
 
except KeyboardInterrupt:
    print("\nScan stopped by user") 
    sys.exit()

except socket.gaierror:
    print("Hostname could not be resolved") 
    sys.exit()   

except socket.error:
    print("Could not connect to server")
    sys.exit()  
      
end=time.time() 
print(f"Scan done in {end-start:.2f} sec")