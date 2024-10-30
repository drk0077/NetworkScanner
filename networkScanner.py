#!/usr/bin/python3
#https://github.com/drk0077
import scapy.all as scapy
import argparse
import requests
import warnings

# Suppress all warnings
warnings.filterwarnings("ignore")

def get_argument():
    parser = argparse.ArgumentParser()
    parser.add_argument("-r", "--range", dest="range", help="Enter the IP range you want to scan")
    return parser.parse_args()

def get_mac_vendor(mac):
    url = f"https://api.macvendors.com/{mac}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.text
    else:
        return "Unknown"

def netscan(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    clients = []
    for element in answered_list:
        mac_vendor = get_mac_vendor(element[1].hwsrc)
        clients.append({"ip": element[1].psrc, "mac": element[1].hwsrc, "vendor": mac_vendor})
    return clients

def show_result(result_list):
    print("-------------------------------------------------------------------------\n IP \t\t\t MAC \t\t\t\t  VENDOR \n-------------------------------------------------------------------------")
    for client in result_list:
        print(f"{client['ip']} \t\t {client['mac']} \t\t {client['vendor']}")

args = get_argument()
scan_result = netscan(args.range)
show_result(scan_result)

