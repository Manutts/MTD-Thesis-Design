import threading
import random
import hashlib
from scapy.all import *

packets = rdpcap("modbus_traffic.pcap")
modbus_packets = [pkt for pkt in packets if pkt.haslayer(ModbusADU)]

# Define the two sets of IP addresses
real_ips = {'192.168.0.1', '192.168.0.2', '192.168.0.3'}
virtual_ips = set()

# Define the two sets of port numbers
real_ports = {502, 503}
virtual_ports = set()

# Function to periodically randomize the virtual IP addresses
def randomize_ips():
    global virtual_ips
    virtual_ips = {f"192.168.{random.randint(0, 255)}.{random.randint(0, 255)}" for _ in real_ips}
    threading.Timer(300, randomize_ips).start()  # Call this function again after 300 seconds

# Function to periodically randomize the virtual port numbers
def randomize_ports():
    global virtual_ports
    virtual_ports = {random.randint(1024, 65535) for _ in real_ports}
    threading.Timer(60, randomize_ports).start()  # Call this function again after 60 seconds

def virtual_ip_for_real_ip(real_ip):
    # Convert the real IP address to bytes
    real_ip_bytes = bytes(real_ip, 'utf-8')
    
    # Compute a hash of the real IP address
    hash_obj = hashlib.sha256(real_ip_bytes)
    hash_bytes = hash_obj.digest()
    
    # Use the first four bytes of the hash as the virtual IP address
    virtual_ip_bytes = hash_bytes[:4]
    
    # Convert the virtual IP address back to a string
    virtual_ip = ".".join(str(b) for b in virtual_ip_bytes)
    
    return virtual_ip

def virtual_port_for_real_port(real_port):
    # Generate a unique virtual port number based on the real port number
    # Use a hash function to map the real port to a virtual port
    virtual_port = (real_port * 31) % 32768 + 1024
    while virtual_port in virtual_ports:
        # If the virtual port number is already in use, generate a new one
        virtual_port = (virtual_port * 31) % 32768 + 1024
    virtual_ports.add(virtual_port)
    return virtual_port

# Code to process Modbus packets
for pkt in modbus_packets:
    if pkt.src in real_ips and pkt.dst in real_ips:
        # Communication via real attributes
        src_ip = pkt.src
        dst_ip = pkt.dst
        src_port = pkt.src_port
        dst_port = pkt.dst_port
        adu = ModbusAU(pkt.payload)

         # Process the ModbusADU then build and send new Modbus Packet
        new_pkt = Ether(src=pkt.src, dst=pkt.dst)/IP(src=pkt.src, dst=pkt.dst)/TCP(sport=pkt.sport, dport=pkt.dport)/adu.build()
        send(new_pkt)
    elif pkt.src in virtual_ips and pkt.dst in virtual_ips:
        # Communication via random attributes
        src_ip = pkt.src
        dst_ip = pkt.dst
        dst_port = virtual_port_for_real_port(pkt.dst_port)
        adu = ModbusADU(pkt.payload)
        # ...
        new_pkt = Ether(src=pkt.src, dst=pkt.dst)/IP(src=pkt.src, dst=pkt.dst)/TCP(sport=random.choice(list(virtual_ports)), dport=dst_port)/adu.build()
        send(new_pkt)
    elif pkt.dst in virtual_ips:
        # Communication via random port number
        src_ip = pkt.src
        dst_ip = pkt.dst
        src_port = pkt.src_port
        dst_port = virtual_port_for_real_port(pkt.dst_port)
        # ...
        new_pkt = Ether(src=pkt.src, dst=pkt.dst)/IP(src=pkt.src, dst=pkt.dst)/TCP(sport=random.choice(list(virtual_ports)), dport=dst_port)/adu.build()
        send(new_pkt)
    else:
        # Drop
        continue
