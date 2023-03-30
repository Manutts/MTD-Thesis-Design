import random
import socket

# Function to generate a random IP address
def generate_random_ip():
    # Use a list comprehension to generate four random integers between 0 and 255,
    # then join them together with periods to form a valid IP address string
    ip = ".".join(str(random.randint(0, 255)) for _ in range(4))
    return ip

# Function to generate a random MAC address
def generate_random_mac():
    # Create a list with the OUI prefix (first three values) and three random integers between 0 and 255
    mac = [0x00, 0x16, 0x3e,
           random.randint(0x00, 0x7f),
           random.randint(0x00, 0xff),
           random.randint(0x00, 0xff)]
    # Join the integers together with colons to form a valid MAC address string
    return ':'.join(map(lambda x: "%02x" % x, mac))

# Function to generate a random port number
def generate_random_port():
    # Generate a random integer between 1024 and 65535, which are the valid port numbers for TCP and UDP protocols
    return random.randint(1024, 65535)

# Generate a random IP address, MAC address, and port number
ip = generate_random_ip()
mac = generate_random_mac()
port = generate_random_port()

# Print out the results
print("Random IP address: {}".format(ip))
print("Random MAC address: {}".format(mac))
print("Random port number: {}".format(port))

# Prompt the user to enter a list of allowed IP addresses, separated by commas
allowed_ips = ['192.168.95.2', '192.168.95.5', '192.168.95.10']

ip = generate_random_ip()

# Function to check if an IP address is in the allowed list
def is_ip_allowed(ip):
    return ip in allowed_ips

if is_ip_allowed(ip):
    print("Access granted for IP address: {}".format(ip))
else:
    print("Access denied for IP address: {}".format(ip))