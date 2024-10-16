import os
import json
import subprocess
import threading
import time
from scapy.all import sniff, ICMP, IP
import paramiko

# Constants
ARP_PREFIX = "192.168.68."  # Placeholder; will be determined dynamically
ARP_START = 201            # Starting octet for fake IPs
ARP_END = 210              # Ending octet for fake IPs
MAX_MESSAGE_LENGTH = 60
MAC_ADDRESS_FORMAT = "{}:{}:{}:{}:{}:{}"

# Load character to MAC mapping
def load_mapping():
    with open('char_to_mac.json', 'r') as file:
        return json.load(file)

# Determine subnet based on Initiator's IP
def determine_subnet(initiator_ip):
    octets = initiator_ip.split('.')
    if len(octets) != 4:
        raise ValueError("Invalid IP address format.")
    return '.'.join(octets[:3]) + '.'

# Validate and get user message
def get_user_message(mapping):
    allowed_chars = set(mapping.keys())
    while True:
        message = input(f"Enter a message (up to {MAX_MESSAGE_LENGTH} characters): ")
        if len(message) > MAX_MESSAGE_LENGTH:
            print(f"Message too long. Truncated to {MAX_MESSAGE_LENGTH} characters.")
            message = message[:MAX_MESSAGE_LENGTH]
        if all(char in allowed_chars for char in message):
            return message
        else:
            print("Message contains invalid characters. Allowed characters are letters, numbers, space, underscore, dash, and dot.")

# Convert message to MAC addresses
def convert_message_to_mac(message, mapping):
    encoded = ''.join([mapping[char] for char in message])
    # Each MAC address requires 12 hex characters (6 octets)
    mac_addresses = []
    for i in range(0, len(encoded), 12):
        chunk = encoded[i:i+12]
        if len(chunk) < 12:
            chunk = chunk.ljust(12, '0')  # Pad with '0's
        mac = MAC_ADDRESS_FORMAT.format(*[chunk[j:j+2] for j in range(0, 12, 2)])
        mac_addresses.append(mac)
    return mac_addresses

# Add static ARP entries
def add_arp_entries(mac_addresses, subnet):
    for idx, mac in enumerate(mac_addresses, start=ARP_START):
        ip = f"{subnet}{idx}"
        command = f"sudo arp -s {ip} {mac}"
        result = os.system(command)
        if result == 0:
            print(f"Added ARP entry: {ip} -> {mac}")
        else:
            print(f"Failed to add ARP entry: {ip} -> {mac}")

# Send ping to Initiator
def send_ping(initiator_ip, size=56):
    print(f"Pinging Initiator at {initiator_ip} to signal message is ready...")
    subprocess.run(["ping", "-c", "1", "-s", str(size), initiator_ip])

# Listen for incoming pings from Initiator
def listen_for_ping(initiator_ip, callback):
    def packet_callback(packet):
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            if packet[IP].src == initiator_ip:
                print(f"Received ping from {initiator_ip}.")
                callback()
    sniff(filter="icmp", prn=packet_callback, store=0)

# SSH into Initiator to read its ARP cache
def read_initiator_message(initiator_ip, ssh_username, ssh_password, mapping, subnet):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(initiator_ip, username=ssh_username, password=ssh_password)
        stdin, stdout, stderr = ssh.exec_command("arp -an | grep '^" + subnet + "'")
        arp_output = stdout.read().decode()
        ssh.close()
        
        arp_entries = []
        for line in arp_output.splitlines():
            parts = line.split()
            if len(parts) >= 4:
                ip = parts[1].strip('()')
                mac = parts[3].replace(':', '')
                arp_entries.append(mac)
        
        # Decode MAC addresses to message
        decoded = ""
        reverse_mapping = {v: k for k, v in mapping.items()}
        for mac in arp_entries:
            for i in range(0, len(mac), 2):
                pair = mac[i:i+2]
                if pair in reverse_mapping:
                    decoded += reverse_mapping[pair]
        print(f"Message from Initiator: {decoded}")
    except Exception as e:
        print(f"Error reading Initiator's message: {e}")

# Cleanup function
def cleanup(subnet):
    print("Performing cleanup...")
    # Clear ARP cache entries within the subnet and ARP_START to ARP_END
    for idx in range(ARP_START, ARP_END + 1):
        ip = f"{subnet}{idx}"
        command = f"sudo arp -d {ip}"
        os.system(command)
    print("ARP cache entries cleared.")
    # Clear SSH auth logs (Linux specific)
    try:
        os.system("sudo truncate -s 0 /var/log/auth.log")
        print("SSH logs cleared.")
    except Exception as e:
        print(f"Failed to clear SSH logs: {e}")
    # Confirmation message
    print("Cleanup completed.")
    time.sleep(3)
    # Clear terminal
    os.system('clear')

# Main function for Responder
def main():
    mapping = load_mapping()
    
    # Step 1: Get Initiator's IP and SSH credentials
    initiator_ip = input("Enter the Initiator's IP address: ")
    try:
        subnet = determine_subnet(initiator_ip)
    except ValueError as ve:
        print(ve)
        return
    
    ssh_username = input("Enter the SSH username for the Initiator: ")
    ssh_password = input("Enter the SSH password for the Initiator: ")
    
    # Step 2: Start listening for pings from Initiator in a separate thread
    def on_message_ping():
        print(f"Ping received from {initiator_ip}. Proceeding to read Initiator's message.")
        read_initiator_message(initiator_ip, ssh_username, ssh_password, mapping, subnet)
        
        # Confirm reading
        confirm = input("Did you read the message? (y/n): ").lower()
        if confirm == 'y':
            # Optionally send a message back
            send_reply = input("Do you want to send a message back? (y/n): ").lower()
            if send_reply == 'y':
                reply_message = get_user_message(mapping)
                reply_mac_addresses = convert_message_to_mac(reply_message, mapping)
                add_arp_entries(reply_mac_addresses, subnet)
                if input("Reply message embedded in ARP cache. Send ping to Initiator? (y/n): ").lower() == 'y':
                    send_ping(initiator_ip)
    
    listener_thread = threading.Thread(target=listen_for_ping, args=(initiator_ip, on_message_ping), daemon=True)
    listener_thread.start()
    
    print("Listening for pings from Initiator...")
    
    # Keep the main thread alive to continue listening
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nExiting Responder.")
        cleanup(subnet)

if __name__ == "__main__":
    main()
