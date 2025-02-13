
# Network Traffic Sniffer and Anomaly Detection

This Python-based network sniffer captures and analyzes network traffic. It helps detect potential security threats by analyzing the traffic for suspicious IP addresses, anomalous ports, and common attacks like SYN flooding.

## Features:
- Captures and analyzes network traffic using `scapy`.
- Detects suspicious IP addresses and anomalous port usage.
- Identifies SYN flooding (common DDoS attack).
- Customizable detection rules (e.g., suspicious IPs, ports).

## Requirements

- Python 3.x
- `scapy` library (Install via `pip install scapy`)
- Root or administrator privileges to capture network traffic (use `sudo` on Linux or Mac).

## Installation

1. Clone this repository:
    ```bash
    git clone https://github.com/yourusername/network-traffic-sniffer.git
    ```

2. Navigate to the project directory:
    ```bash
    cd network-traffic-sniffer
    ```

3. Install the required Python libraries:
    ```bash
    pip install scapy
    ```

## Usage

1. Edit the script to define suspicious IPs, ports, or any other anomalies you'd like to track.

2. Run the script with root privileges (on Linux or Mac, use `sudo`):
    ```bash
    sudo python network_sniffer.py
    ```

3. The script will start capturing packets and analyze the traffic. The script will print alerts for suspicious activities such as:
   - Suspicious IP address traffic.
   - Anomalous port usage.
   - SYN packets (potential SYN flooding attack).

4. You can stop the sniffer anytime by pressing `Ctrl+C`.

### Example Output:

