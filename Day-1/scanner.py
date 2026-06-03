import socket

# Configuration variables
target = "scanme.nmap.org"
port = 80

# Initialize the network socket
s = socket.socket()
s.settimeout(1)

# Attempt to connect to the target port
result = s.connect_ex((target, port))

# Check and print the connection result
if result == 0:
    print(f"Port {port} is Open")
else:
    print(f"Port {port} is Closed")

# Release the socket resource
s.close()
