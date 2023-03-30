from scapy.all import *
import modbus_tk.defines as cst
import modbus_tk.modbus_tcp as modbus_tcp
import json
import socket
import random

# Define a list of allowed IP addresses
allowed_ips = ['192.168.95.2', '192.168.95.5', '192.168.95.10']

# Define a range of valid port numbers
min_port = 1024
max_port = 65535

# Retrieve current IP address and MAC address
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect(('8.8.8.8', 1))
current_ip = s.getsockname()[0]
current_mac = ':'.join(['{:02x}'.format((int(i, 16) + random.randint(0, 255)) % 256) for i in current_mac.split(':')])

# Generate a random IP address that is not in the allowed list
while True:
    new_ip = '192.168.95.' + str(random.randint(1, 254))
    if new_ip not in allowed_ips and new_ip != current_ip:
        break

# Generate a random MAC address that is not in the allowed list
while True:
    new_mac = ':'.join(['{:02x}'.format(random.randint(0, 255)) for _ in range(6)])
    if new_mac != current_mac:
        break

# Generate a random port number that is not already in use
while True:
    new_port = random.randint(min_port, max_port)
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(('0.0.0.0', new_port))
        s.close()
        break
    except:
        pass

# Use the new IP address, MAC address, and port number for communication
print(f"New IP address: {new_ip}")
print(f"New MAC address: {new_mac}")
print(f"New port number: {new_port}")

