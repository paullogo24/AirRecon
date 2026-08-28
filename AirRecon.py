import os
import sys 
import time 
import csv
import json
import subprocess
from datetime import datetime
from scapy.all import *
from scapy.layers.dot11 import *
from tabulate import tabulate

#PROJECT FOLDERS
DATA_DIR = 'data'
LOGS_DIR = 'logs'
REPORTS_DIR = 'reports'
os.makedirs(DATA_DIR, exist_ok=True)
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(REPORTS_DIR, exist_ok=True)

#Config
DEFAULT_INTERFACE = None
SCAN_TIMEOUT = 10
LOG_FILE = os.path.join(LOGS_DIR, "wifi_scan.log")
RESULTS_FILE = os.path.join(DATA_DIR, "wifi_scan_results.json")

#Tool Info
TOOL_NAME = "AirRecon"
TOOL_VERSION = "1.0"
AUTHOR = "paul.l"
DESCRIPTION = "Discover nearby wifi networks analyze their security details"

#Main menu
def show_menu():
    os.system('cls' if os.name == 'nt' else 'clear')
    print("=" * 60)
    print(f"{TOOL_NAME} - Version {TOOL_VERSION}")
    print("=" *60)
    print("1. List Wireless Interfaces")
    print("2. Scan for WiFi Networks")
    print("3. Analyze Selected Network")
    print("4. Generate Report (CSV)")
    print("5. View Saved Results")
    print("6. Exit")
    print("=" * 60)

#Get wifi interfaces
def get_wireless_interfaces():
    interfaces = []
    for iface in os.listdir('/sys/class/net/'):
        if iface != 'lo':
            interfaces.append(iface)
    return interfaces

#Scan wifi networks
def scan_wifi (interface, timeout = 5):
    networks = []
    print(f'[*] Scanning on {interface}... Please  wait {timeout} s')
    os.system(f'iwlist {interface} scan | tee scan_output.txt')
    time.sleep(timeout)
    with open('scan_output.txt', 'r' , errors= 'ignore') as f:
        data = f.read().split('Cell')
        for cell in data:
            if 'ESSID' in cell:
                network = parse_network_info(cell)
                if network:
                    networks.append(network)
    return networks

#parse network info
def parse_network_info(cell):
    network = {}
    network['BSSID']          = re.search(r'Address: \s*([0-9A-Fa-f:]{17})', cell)
    network['ESSID']          = re.search(r'ESSID:"(.*)"', cell)
    network['Channel']        = re.search(r'Channel:(\d+)', cell)
    network['Frequency']      = re.search(r'Frequency:([\d\.]+ )\s*GHz', cell)
    network['Quality']        = re.search(r'Quality=(\d+)/(\d+)', cell)
    network['Encryption']     = detect_encryption(cell)
    network['Signal Level']   = calculate_signal(network['Quality'])

#detect encryption type
def detect_encryption(cell):
    if 'WPA3' in cell:         return "WPA3"
    elif 'WPA2' in cell:       return "WPA2"
    elif 'WPA' in cell:        return "WPA"
    elif 'Privacy' in cell:    return "WEP"
    else:                      return "Open"

def calculate_signal(quality):
    try:
        q, max_q = map(int, quality.groups())
        return int ((q / max_q)) * 100
    except:
        return 0 