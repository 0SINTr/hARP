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

# Send ping to Responder
def send_ping(responder_ip):
    print(f"Pinging Responder at {responder_ip} to signal message is ready...")
    subprocess.run(["ping", "-c", "1", responder_ip])

# Listen for incoming pings from Responder
def listen_for_ping(expected_size, callback):
    def packet_callback(packet):
        if packet.haslayer(ICMP) and packet.haslayer(IP):
            if packet[IP].src == responder_ip:
                if len(packet[ICMP].payload) == expected_size:
                    print(f"Received cleanup ping from {responder_ip}. Initiating cleanup.")
                    callback()
    sniff(filter="icmp", prn=packet_callback, store=0)

# SSH into Responder to read its ARP cache
def read_responder_message(responder_ip, ssh_username, ssh_password, mapping):
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(responder_ip, username=ssh_username, password=ssh_password)
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
        print(f"Message from Responder: {decoded}")
    except Exception as e:
        print(f"Error reading Responder's message: {e}")

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

# Main function
def main():
    global responder_ip  # To be used in the listener
    mapping = load_mapping()
    
    # Step 1: Get Responder's IP
    responder_ip = input("Enter the Responder's IP address: ")
    
    # Step 2: Get user message
    message = get_user_message(mapping)
    
    # Step 3: Convert message to MAC addresses
    mac_addresses = convert_message_to_mac(message, mapping)
    
    # Step 4: Add ARP entries
    add_arp_entries(mac_addresses)
    
    # Step 5: Ask user to send ping
    send_ping_confirm = input("Message embedded in ARP cache. Send ping to Responder? (y/n): ").lower()
    if send_ping_confirm == 'y':
        send_ping(responder_ip)
    
    # Step 6: Start listening for pings from Responder in a separate thread
    def on_cleanup_ping():
        cleanup()
        exit(0)
    
    listener_thread = threading.Thread(target=listen_for_ping, args=(56, on_cleanup_ping), daemon=True)
    listener_thread.start()
    
    print("Listening for pings from Responder...")
    
    # Keep the main thread alive to continue listening
    while True:
        time.sleep(1)

if __name__ == "__main__":
    main()
