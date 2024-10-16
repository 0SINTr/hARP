import os
import json
import subprocess
import socket
import threading
import time
from scapy.all import sniff, ICMP, IP
import paramiko

# Constants
ARP_PREFIX = "1.1.1."
MAX_MESSAGE_LENGTH = 60
MAC_ADDRESS_FORMAT = "{}:{}:{}:{}:{}:{}"

# Load character to MAC mapping
def load_mapping():
    with open('char_to_mac.json', 'r') as file:
        return json.load(file)

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
def add_arp_entries(mac_addresses):
    for idx, mac in enumerate(mac_addresses, start=1):
        ip = f"{ARP_PREFIX}{idx}"
        command = f"sudo arp -s {ip} {mac}"
        os.system(command)
        print(f"Added ARP entry: {ip} -> {mac}")

# Send ping to Initiator
def send_ping(initiator_ip, size=56):
    print(f"Pinging Initiator at {initiator_ip} to signal message is ready...")
    subprocess.run(["ping", "-c", "1", "-s", str(size), initiator_ip])

# Listen for incoming pings from Initiator
def listen_for_ping(expected_size, callback):
    def packet_callback(packet):
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            if packet[IP].src == initiator_ip:
                if len(packet[ICMP].payload) == expected_size:
                    print(f"Received cleanup ping from {initiator_ip}. Initiating cleanup.")
                    callback()
    sniff(filter="icmp", prn=packet_callback, store=0)

# SSH into Initiator to read its ARP cache
def read_initiator_message(initiator_ip, ssh_username, ssh_password, mapping):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(initiator_ip, username=ssh_username, password=ssh_password)
        stdin, stdout, stderr = ssh.exec_command("arp -an | grep '^1.1.1.'")
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
def cleanup():
    print("Performing cleanup...")
    # Clear ARP cache
    os.system("sudo arp -d -a")
    print("ARP cache cleared.")
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

# Listen for pings in a separate thread
def listen_for_initial_ping(initiator_ip, ssh_username, ssh_password, mapping):
    def on_ping_received():
        print(f"Ping received from {initiator_ip}.")
        proceed = input("Do you want to read the Initiator's message? (y/n): ").lower()
        if proceed == 'y':
            read_initiator_message(initiator_ip, ssh_username, ssh_password, mapping)
            confirm = input("Did you read the message? (y/n): ").lower()
            if confirm == 'y':
                # Optionally send a message back
                send_reply = input("Do you want to send a message back? (y/n): ").lower()
                if send_reply == 'y':
                    message = get_user_message(mapping)
                    mac_addresses = convert_message_to_mac(message, mapping)
                    add_arp_entries(mac_addresses)
                    if input("Message embedded in ARP cache. Send ping to Initiator? (y/n): ").lower() == 'y':
                        send_ping(initiator_ip)
    # Start listener
    print("Listening for pings from Initiator...")
    sniff(filter="icmp", prn=lambda pkt: handle_ping(pkt, initiator_ip, on_ping_received), store=0)

def handle_ping(packet, initiator_ip, callback):
    if packet.haslayer(ICMP) and packet.haslayer(IP):
        if packet[IP].src == initiator_ip:
            print(f"Ping received from {initiator_ip}.")
            callback()

# Main function
def main():
    global initiator_ip
    mapping = load_mapping()
    
    # Step 1: Get Initiator's IP and SSH credentials
    initiator_ip = input("Enter the Initiator's IP address: ")
    ssh_username = input("Enter the SSH username for the Initiator: ")
    ssh_password = input("Enter the SSH password for the Initiator: ")
    
    # Step 2: Start listening for pings from Initiator in a separate thread
    def on_initial_ping():
        print(f"Ping received from {initiator_ip}.")
        proceed = input("Do you want to read the Initiator's message? (y/n): ").lower()
        if proceed == 'y':
            read_initiator_message(initiator_ip, ssh_username, ssh_password, mapping)
            confirm = input("Did you read the message? (y/n): ").lower()
            if confirm == 'y':
                # Optionally send a message back
                send_reply = input("Do you want to send a message back? (y/n): ").lower()
                if send_reply == 'y':
                    message = get_user_message(mapping)
                    mac_addresses = convert_message_to_mac(message, mapping)
                    add_arp_entries(mac_addresses)
                    if input("Message embedded in ARP cache. Send ping to Initiator? (y/n): ").lower() == 'y':
                        send_ping(initiator_ip)
    
    listener_thread = threading.Thread(target=listen_for_initial_ping, args=(initiator_ip, ssh_username, ssh_password, mapping), daemon=True)
    listener_thread.start()
    
    # Keep the main thread alive to continue listening
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
