#! /usr/bin/python

import socket
import subprocess
import sys
import os
import argparse
import ipaddress
from scapy.all import *
from fpdf import FPDF

# Functions
# Using the range function to specify ports (here it will scans all ports between 1 and 1024)
# scan depending on TCP and UDP
#code based on http://pythonexample.com/code/python-scan-udp-port/
def scan( port, targetIP, scantype, hostlist ):
    sock = socket.socket(socket.AF_INET, scantype) #SOCK_DGRAM FOR UDP
    result = sock.connect_ex((targetIP, port))
    if result == 0:
        templist = [targetIP, port]
        print("Port {}:\t\t| Open".format(port))
        hostlist.append(templist)
        sock.close()
        return 1
    sock.close()
    return 0

# Clear screen to allow for running
subprocess.call('clear', shell=True)

# Collect User Input (use an argument parser)
parser= argparse.ArgumentParser(description='process some arguments.')
parser.add_argument('-t', '--target', nargs='+', help="IP address of target machine/host, can be a single IP address, subnet, or enter two IP addresses for a range", default="no_value")
parser.add_argument('-p', '--port', help="Port to be scanned", type=int, nargs='*', default=range(1025))
parser.add_argument('-u', '--udp', action="store_true", help="scan just UDP ports")
parser.add_argument('-e', '--export', action="store_true", help="export results to PDF")
parser.add_argument('-r', '--traceroute', action="store_true", help="conduct a traceroute of the target host")
parser.add_argument('-x', '--ping', action="store_true", help="conduct a ping of the target host")
args = parser.parse_args()

# Assign Variables
target = args.target
target_port = args.port
udp = args.udp
export = args.export
trace = args.traceroute
ping = args.ping

scantype = socket.SOCK_STREAM
if udp:
    scantype = socket.SOCK_DGRAM

# Check if range was given
if len(target) > 1:
    target_range = []
    for ipaddr in range(int(ipaddress.IPv4Address(target[0])), int(ipaddress.IPv4Address(target[1])+1)):
        target_range.append(ipaddress.IPv4Address(ipaddr))
    target = target_range

# Get Target IP
for host in target:
    for address in ipaddress.IPv4Network(host):
        address = str(address)
        results = 0
        hostlist = []
        targetIP = socket.gethostbyname(address)

        # Print a nice banner with information on which host we are about to scan
        try:
            print('#' * 80, '\n')
            print("Scanning target", targetIP)
            print('-' * 80)
        except:
            print('Could not connect to host. Invalid target address/host')

        # Added error checking by use of try and except
        # Counted results returned for later use
        try:
            print('Port No.\t\t| Status')
            print('-' * 80)
            
            for port in target_port:
                results += scan( port , targetIP, scantype , hostlist)
            
            print('\nThe scan for',address, 'resulted in {} open port(s).\n\n'.format(results))
            
        
        except KeyboardInterrupt:
            print('-' * 80)
            print('\nScan cancelled by user before it could finish.')
            sys.exit()

        except socket.gaierror:
            print('-' * 80)
            print('Could not resolve target')
            sys.exit()

        except socket.error:
            print('-' * 80)
            print('Could not connect. Port is likely closed')
            sys.exit()
        
        # check for traceroute flag
        if trace:
            try:
                response = subprocess.call(["tracert", "-m 16", address])
            except:
                response = subprocess.call(["traceroute", "-m 16", address])
            print(response)

        # ICMP (Ping)
        if ping:
            response = os.system("ping -c 1 " + address)
            print(response)
   

# PDF printing of results
if export:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", size=12)
    pdf.cell(200, 10, txt="Scan Results", ln=1, align="C")
    pdf.set_font("Arial", size=8)
    for host in hostlist:
        pdf.cell(200, 10, txt='Host: {}      Port: {}      Status: Open'.format(host[0],host[1]) , ln=1, align="L")
    pdf.output("ScanResults.pdf")
    print("File 'ScanResults.pdf' exported successfully\n")




###############################     UNUSED CODE     #################################################
# def scanudp( port, targetIP ):
#     ip = IP(dst=targetIP)
#     udp = UDP(dport=port,sport = 123)
#     packet = ip/udp
#     response = sr(packet,verbose=False,timeout = 5)
#     result = response[0][ICMP][0][1][ICMP]
#     print(result)
#     if result == 0:
#         print("Port {} on {} is open|filtered".format(port,targetIP))
#         return 1
#     return 0
    # udp_scan_resp = sr1(IP(dst=targetIP)/UDP(dport=int(port)),timeout=10)
    # print(udp_scan_resp)
    # if (str(type(udp_scan_resp))=="<type 'NoneType'>"):
    #     print('test')
    #     retrans = []
    #     for count in range(0,3):
    #         retrans.append(sr1(IP(dst=targetIP)/UDP(dport=int(port)),timeout=10))
    #     for item in retrans:
    #         if (str(type(item))!="<type 'NoneType'>"):
    #             udp_scan(targetIP,port,10)
    #     return "Open|Filtered"
    # elif (udp_scan_resp.haslayer(UDP)):
    #     return "Open"
    # elif (udp_scan_resp.haslayer(ICMP)):
    #     if(int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code)==3):
    #         return "Closed"
    #     elif (int(udp_scan_resp.getlayer(ICMP).type)==3 and int(udp_scan_resp.getlayer(ICMP).code) in [1,2,9,10,13]):
    #         return "Filtered"
    # else:
    #     return "CHECK"