import psutil
import socket
import argparse
import logging
import requests
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Set up logging
logging.basicConfig(filename='external_connections.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# VirusTotal API Key
VIRUSTOTAL_API_KEY = '460392ddb633d8e5d880b5244d09982c0d3c80d34350430d0222c7aac7399ae7'

# Logo
logo = """
   ____ _____ _    ____ ____  ____
  / ___| ____| |  / ___|  _ \/ ___|
 | |  _|  _| | | | |   | | | \___ \
 | |_| | |___| | | |___| |_| |___) |
  \____|_____|_|  \____|____/|____/
"""

def resolve_hostname(ip):
    try:
        return socket.gethostbyaddr(ip)[0]
    except socket.herror:
        return ip

def check_virustotal(api_key, ip):
    """Check if the IP is malicious using the VirusTotal API."""
    url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
    params = {
        'apikey': api_key,
        'ip': ip,
    }
    response = requests.get(url, params=params)
    if response.status_code == 200:
        result = response.json()
        if 'detected_urls' in result and result['detected_urls']:
            return Fore.RED + "Malicious" + Style.RESET_ALL
        else:
            return Fore.GREEN + "Clean" + Style.RESET_ALL
    return Fore.YELLOW + "Unknown" + Style.RESET_ALL

def display_external_connections(filter_state=None, resolve_hostnames=False, check_virus_total=False):
    try:
        connections = psutil.net_connections(kind='inet')
        print("External connections:")
        print(logo)  # Print logo
        print("{:<20} {:<15} {:<40} {:<15} {:<10} {:<10}".format(
            "Local Address", "Remote IP", "Hostname (Resolved)", "Status", "PID", "VirusTotal"
        ))
        
        for conn in connections:
            if conn and conn.laddr and conn.raddr and conn.raddr.ip != '127.0.0.1':
                if filter_state and conn.status != filter_state:
                    continue

                local_address = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote_ip = conn.raddr.ip if conn.raddr else "N/A"
                remote_port = conn.raddr.port if conn.raddr else "N/A"
                remote_address = f"{remote_ip}:{remote_port}"

                resolved_name = resolve_hostname(remote_ip) if resolve_hostnames else "N/A"
                status = conn.status if conn.status else "UNKNOWN"
                pid = conn.pid if conn.pid else "N/A"
                
                if check_virus_total:
                    vt_status = check_virustotal(VIRUSTOTAL_API_KEY, remote_ip)
                else:
                    vt_status = "Not checked"

                print("{:<20} {:<15} {:<40} {:<15} {:<10} {:<10}".format(
                    local_address,
                    remote_ip,
                    resolved_name,
                    status,
                    pid,
                    vt_status
                ))
                logging.info(f"Local Address: {local_address}, Remote IP: {remote_ip}, "
                             f"Hostname (Resolved): {resolved_name}, Status: {status}, PID: {pid}, "
                             f"VirusTotal: {vt_status}")

    except Exception as e:
        logging.error(f"Error: {e}")
        print(f"Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Display established external connections.')
    parser.add_argument('--filter-state', type=str, help='Filter connections by state (e.g., ESTABLISHED)')
    parser.add_argument('--resolve-hostnames', action='store_true', help='Resolve IP addresses to hostnames')
    parser.add_argument('--check-virus-total', action='store_true', help='Check IP addresses against VirusTotal')

    args = parser.parse_args()
    display_external_connections(
        filter_state=args.filter_state, 
        resolve_hostnames=args.resolve_hostnames, 
        check_virus_total=args.check_virus_total
    )
