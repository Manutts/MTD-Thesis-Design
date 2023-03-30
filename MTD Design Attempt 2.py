from scapy.all import *
import random

# define the real and virtual port numbers
rPort1 = 1234
vPort1 = 50000
rPort2 = 5678
vPort2 = 60000

# create a packet processing function
def process_packet(pkt):
    # check if packet is from h1 to h2
    if pkt[IP].src == 'h1' and pkt[IP].dst == 'h2':
        # check if communication is authorized
        if pkt[TCP].sport == rPort1 and pkt[TCP].dport == rPort2:
            # set packet source and destination ports to real values
            pkt[TCP].sport = rPort1
            pkt[TCP].dport = rPort2
        else:
            # set packet source and destination ports to virtual values
            pkt[TCP].sport = vPort1
            pkt[TCP].dport = vPort2
    # check if packet is from h2 to h1
    elif pkt[IP].src == 'h2' and pkt[IP].dst == 'h1':
        # check if communication is authorized
        if pkt[TCP].sport == rPort2 and pkt[TCP].dport == rPort1:
            # set packet source and destination ports to real values
            pkt[TCP].sport = rPort2
            pkt[TCP].dport = rPort1
        else:
            # set packet source and destination ports to virtual values
            pkt[TCP].sport = vPort2
            pkt[TCP].dport = vPort1
    # drop all other packets
    else:
        return

    # send the modified packet
    send(pkt)

# start sniffing packets and processing them
sniff(filter='host h1 or host h2', prn=process_packet)