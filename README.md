# hARP: Covert Communication via ARP Cache 🕵️‍♂️

**hARP** is a covert communication tool that enables two hosts on the same network to exchange messages by manipulating their ARP caches. By embedding messages into static ARP entries, hARP allows for discreet data exchange without raising suspicions from standard network monitoring tools.

🍀 **NOTE:** This is an ongoing **reasearch project** for educational purposes rather than a full-fledged production-ready tool, so treat it accordingly.

## 📋 Table of Contents

- [Advantages](#advantages)
- [How It Works](#how-it-works)
- [System Requirements](#system-requirements)
- [Installation and Setup](#installation-and-setup)
- [Usage](#usage)
- [Security Considerations](#security-considerations)
- [🎯 Planned Upgrades](#-planned-upgrades)
- [⚠️ Disclaimer](#-disclaimer)
- [📜 License](#-license)
- [📧 Contact](#-professional-collaborations)

## 🎯 Advantages

- **Stealthy Communication**: hARP leverages ARP cache entries to hide messages, making it difficult for traditional network security tools to detect the communication.
- **Minimal Network Footprint**: By using ARP cache manipulation and minimal ICMP pings, hARP avoids generating significant network traffic.
- **No Additional Network Services Required**: Operates without the need for extra network services or open ports, reducing exposure to network scans.
- **Customizable and Extensible**: Users can extend the character mapping to support additional characters or symbols as needed.

## 🛠️ How It Works

hARP consists of two main components: the **Initiator** and the **Responder**. The communication flow between them involves the following steps:

1. **Initialization**:
   - The Initiator and Responder agree on a range of IP addresses within their shared subnet to use for ARP cache manipulation.
   - Both hosts ensure that they have SSH access to each other for reading ARP caches remotely.

2. **Message Encoding**:
   - **Initiator**:
     - The user inputs a message for the Responder to read.
     - The message is converted into a series of MAC addresses using a predefined character-to-hex mapping.
     - More specifically, each character is mapped to a MAC address octet as per **char_to_mac.json**.
     - Static ARP entries are created on the Initiator's host, associating each MAC address with a unique IP address within the agreed range.
   - **Responder**:
     - Waits for a signal (ping) from the Initiator.

3. **Communication Trigger**:
   - The Initiator sends an ICMP ping to the Responder, signaling that the message is ready to be read.

4. **Message Retrieval**:
   - **Responder**:
     - Upon receiving the ping, the Responder SSHes into the Initiator's host to read the ARP cache entries.
     - Extracts the MAC addresses associated with the agreed IP range and orders them by last IP octet.
     - Decodes the MAC addresses back into the original message using the reverse character mapping.
     - Displays the message to the user.

5. **Replying**:
   - **Responder**:
     - The Responder user can input a reply message following the same encoding process.
     - Static ARP entries are created on the Responder's host.
     - Sends an ICMP ping back to the Initiator to signal that the reply is ready.
   - **Initiator**:
     - Upon receiving the ping, the Initiator SSHes into the Responder's host to read the ARP cache and retrieve the reply message.

6. **Confirmation and Cleanup**:
   - Both the Initiator and Responder send confirmation pings after reading messages.
   - Upon receiving the confirmation, both hosts perform cleanup:
     - Remove the static ARP entries created in the ARP cache.
     - Clear SSH logs to minimize traces of the communication.
     - Clear the terminal screen.

## 🖥️ System Requirements

- **Operating System**: Linux-based systems (tested on Ubuntu, Kali Linux)
- **Python**: Python 3.8 or higher
- **Python Packages**:
  - `scapy`
  - `paramiko`
- **Network Configuration**:
  - Both hosts must be on the same subnet.
  - SSH server running on both hosts.
  - Mutual SSH access with appropriate credentials or SSH keys.
- **Privileges**:
  - Administrative (sudo) privileges to modify ARP cache entries and clear logs.

## ⚙️ Installation and Setup

### 1. Clone the Repository

```bash
git clone https://github.com/0SINTr/hARP.git
cd hARP/harp
```

### 2. Install Required Python Packages

```bash
sudo apt install python3-scapy
sudo apt install python3-paramiko
```

### 3. Configure SSH Access
```bash
sudo apt update
sudo apt install openssh-server
sudo systemctl start ssh
sudo systemctl enable ssh
sudo systemctl status ssh
```

🍀 **NOTE:** Default SSH username is host username, default SSH password is host password.

### 4. Update Character Mapping (Optional)
The **char_to_mac.json** file contains the character-to-hex mappings.
Modify or extend the mappings if you need to support additional characters.

## 📝 Usage
### 1. Start the Responder
On the **Responder** host:

```bash
sudo python3 responder.py
```

- Input Prompts:
  - Enter the Initiator's IP address.
  - Enter the SSH username and password (or ensure SSH keys are set up).
- The Responder will wait for a ping from the Initiator.

### 2. Start the Initiator
On the **Initiator** host:

```bash
sudo python3 initiator.py
```

- Input Prompts:
  - Enter the Responder's IP address.
  - Enter the SSH username and password (or ensure SSH keys are set up).
  - Enter your message (up to 60 characters).
- The Initiator will embed the message in ARP cache entries and send a ping to the Responder.

### 3. Message Exchange
- Responder:
  - Receives the ping and reads the message from the Initiator's ARP cache.
  - Displays the message to the user.
  - Inputs a reply message.
  - Embeds the reply in ARP cache entries and sends a ping back to the Initiator.

- Initiator:
  - Receives the ping and reads the reply message from the Responder's ARP cache.
  - Displays the reply message to the user.
  - Sends a confirmation ping to the Responder.

### 4. Cleanup
- Upon receiving the confirmation ping, both hosts:
  - Remove the static ARP entries created during the session.
  - Clear SSH logs.
  - Clear the terminal screen.

## ⛑️ Security Considerations
- **Administrative Privileges**: hARP requires sudo privileges, so ensure that only trusted users have access to the scripts.
- **Network Impact**: Manipulating ARP tables can have unintended consequences on network operations. Use hARP in controlled environments.
- **SSH Credentials**: Be cautious with SSH passwords. It's recommended to use SSH keys.
- **Log Clearing**: Clearing logs may violate organizational policies. Ensure compliance before using hARP.

## 🎯 Planned Upgrades

- [ ] More testing is needed
- [ ] Improved CLI experience

## ️⚠️ Disclaimer
**hARP** is intended for educational and authorized security testing purposes only. Unauthorized interception or manipulation of network traffic is illegal and unethical. Users are responsible for ensuring that their use of this tool complies with all applicable laws and regulations. The developers of **hARP** do not endorse or support any malicious or unauthorized activities. Use this tool responsibly and at your own risk.

## 📜 License
**hARP** is licensed under the [GNU GENERAL PUBLIC LICENSE Version 3](https://github.com/0SINTr/hARP/blob/main/LICENSE).

## 📧 Professional Collaborations

- **Email Address**:  
  Please direct your inquiries to **sintr.0@pm.me**.

- **Important Guidelines**:  
  - Use a **professional email** or a **ProtonMail** address.
  - Keep your message **concise** and written in **English**.

- **Security Notice**:  
  Emails with **links** or **attachments** will be ignored for security reasons.