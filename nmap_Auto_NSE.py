#  nmap_Auto_NSE   -   A tool for Automating Infra VA with nmap Enumeration also with service based NSE script scan functionality
#
#
#   A tool for Automating Infrastructure Vunlerability Assessment with automating 
#   nmap enumeration with service-based NSE (Nmap Script Engine) script scans according 
#   to each service that identified from scan. Also you can import nmap output (.xml file) 
#   and it will initiate service-based NSE script scans for each IPs.
#
#
#
#   Author : Roshan N 
#   Github : https://github.com/Dexter-Universe
#   Twitter: @0x d3X73r
#
#
#
#
#
import subprocess
import nmap
import socket
import sys
import re
import xml.etree.ElementTree as etree
import xml.etree.ElementTree as ET
import os
import csv
import time

# Defining ANSI colour codes
class colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    END = '\033[0m'  # Reset color to default


def read_nmap_xml(file_name):
    try:
        tree = ET.parse(file_name)
        root = tree.getroot()
        return root
    except FileNotFoundError:
        print("File not found!")
        return None
    except ET.ParseError:
        print("Error parsing XML file!")
        return None

def filter_and_group_by_service(root):
    service_groups = {}

    for host in root.findall('.//host'):
        ip = host.find('.//address').attrib.get('addr', '')  # Using .get() to handle missing attribute
        for port in host.findall('.//port'):
            service_elem = port.find('.//service')
            if service_elem is None:
                continue  # Skip this port if no service element found
            service_name = service_elem.attrib.get('name', '')  # Using .get() to handle missing attribute
            port_number = port.attrib.get('portid', '')  # Using .get() to handle missing attribute
            if service_name not in service_groups:
                service_groups[service_name] = []
            service_groups[service_name].append({'ip': ip, 'port': port_number})

    return service_groups

def xml_processing(cc, p):
    service_groups = {}  # Initialize service_groups

    if p == 0:
        file_name = f'{cc}tcp.xml'  
    elif p == 1:
        file_name = f'{cc}'  
    else:
        print("Invalid value for 'p'. It should be either 0 or 1.")
        return service_groups  

    if not os.path.isfile(file_name):
        print("Nmap XML output file not found!")
        return service_groups  

    root = read_nmap_xml(file_name)
    if not root:
        print("Error parsing XML file!")
        return service_groups  

    service_groups = filter_and_group_by_service(root)  
    for service_name, entries in service_groups.items():
        print(f"Service: {service_name}")
        for entry in entries:
            print(f"\tIP: {entry['ip']}, Port: {entry['port']}")
        print()

    return service_groups  

def service_nse_scan(ip_addr, batch, service_groups):
    print(colors.BLUE+"\t\t\tService Based Script Scan Running....>"+colors.END)
    
    # nmap command indakkunnu
    for service_name, entries in service_groups.items():
        scanning_command = ["nmap", "-sV", "-v", "-Pn", "-T4"]
        ports = ','.join(entry['port'] for entry in entries)
        scanning_command.extend(["-p", ports])
        ips = ' '.join(entry['ip'] for entry in entries)
        scanning_command.extend([ "--script=*", f'{service_name}*', "-oA", f'{batch}{service_name}NSE', ips])
    
        # Running the Nmap command
        process = subprocess.Popen(scanning_command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
        output, error = process.communicate()
    
        # Printing the output and error
        print(colors.RED+"Nmap Output:"+colors.END)
        print(output)
    
        if error:
            print(colors.RED+"Error occurred:"+colors.END)
            print(error)
        else:
            print(colors.RED+"Nmap not found in the system."+colors.END)

def full_tcp_scan(ip_addr, batch):
    print(colors.BLUE+"\t\t\tFull Port TCP Scan Running....>"+colors.END)
    scanning_command = f'nmap -sV -v -Pn -T4 -p- -oA {batch}tcp {ip_addr}'
        # ooro commandum ooro function aayi create cheyth onnich call cheyyua
    process = subprocess.Popen(scanning_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    output, error = process.communicate()
    print(colors.BLUE+"Nmap Output:"+colors.END)
    print(output)

    if error:
        print(colors.RED+"Error occurred:"+colors.END)
        print(error)
    else:
        print(colors.RED+"Nmap not found in the system."+colors.END)

def udp_scan(ip_addr, batch):
    print(colors.BLUE+"\t\t\tUDP Port Scan Running....>"+colors.END)
    scanning_command = f'nmap -sVU -v -Pn -T4 --top-ports=1000 -oA {batch}udp {ip_addr}'
    process = subprocess.Popen(scanning_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    output, error = process.communicate()
    print(colors.BLUE+"Nmap Output:"+colors.END)
    print(output)

    if error:
        print(colors.RED+"Error occurred:"+colors.END)
        print(error)
    else:
        print(colors.RED+"Nmap not found in the system."+colors.END)

def vuln_scan(ip_addr, batch):
    print(colors.BLUE+"\t\t\tNSE Script Vuln Scan Running....>"+colors.END)
    scanning_command = f'nmap -sV -v -Pn -T4 -p- --script vuln -oA {batch}vuln {ip_addr}'
    process = subprocess.Popen(scanning_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    output, error = process.communicate()
    print(colors.RED+"Nmap Output:"+colors.END)
    print(output)

    if error:
        print(colors.RED+"Error occurred:"+colors.END)
        print(error)
    else:
        print(colors.RED+"Nmap not found in the system."+colors.END)

def simple_scan(ip_addr, batch):
    print(colors.BLUE+"\t\t\tSimple Port Scan Running....>"+colors.END)
    scanning_command = f'nmap -sV -v -Pn -T4 -oA {batch}simple {ip_addr}'
    process = subprocess.Popen(scanning_command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)
    output, error = process.communicate()
    print(colors.BLUE+"Nmap Output:"+colors.END)
    print(output)

    if error:
        print(colors.RED+"Error occurred:"+colors.END)
        print(error)
    else:
        print(colors.RED+"Nmap not found in the system."+colors.END)
  

def scan(ip_addr, continueflag):
    #nmap scan start
    while continueflag == 0:
        try:
            batch = input(colors.YELLOW+"Enter batch number (eg: b1) : "+colors.END)
            xx = input(colors.YELLOW+"Select scan type :\n\n\t1. All\n\t2. TCP Scan Only (without ping, 0-65535)\n\t3. TCP Scan Plus Service Based Script Scan\n\t4. UDP Scan\n\t5. Vuln Script Scan\n\t6. Simple Scan\n\t7. Exit\n\n"+colors.END+colors.GREEN+"\n\nScan Type : "+colors.END)
            if xx == '1':
                full_tcp_scan(ip_addr, batch)
                udp_scan(ip_addr, batch)
                vuln_scan(ip_addr, batch)
                continueflag = 1
                break
            elif xx == '2':
                full_tcp_scan(ip_addr, batch)
                continueflag = 1
                break
            elif xx == '3':
                # TCP + NSE scan
                full_tcp_scan(ip_addr, batch)
                cc = batch
                p = 0
                print(colors.BLUE+"\n\t\t\tXML Processing.....>"+colors.END)
                service_groups = xml_processing(cc, p)
                if service_groups is not None:
                    service_nse_scan(ip_addr, batch, service_groups)
                    sys.exit(0)
            elif xx == '4':
                udp_scan(ip_addr, batch)
                continueflag = 1
                break
            elif xx == '5':
                vuln_scan(ip_addr, batch)
                continueflag = 1
                break
            elif xx == '6':
                simple_scan(ip_addr, batch)
                continueflag = 1
                break
            elif xx == '7':
                continueflag = 1
                sys.exit(0)
            else:
                print(colors.RED+"' Wrong Input Observed!! Please correct"+colors.END)
            continueflag = 0

        except nmap.PortScannerError:
            print(colors.RED+"Nmap Not Installed"+colors.END, sys.exc_info[0])
            sys.exit(0)
        except:
            print(colors.RED+"Unknown Error!!"+colors.END)
            sys.exit(0)
    return batch

def scan_ip(ip_addr, continueflag):
    # ee function particular ip nne mathram scan cheyyunnu
    batch = "IP1"
    while continueflag == 0:
        try:
            xx = input(colors.YELLOW+"Select scan type :\n\n\t1. All\n\t2. TCP Scan Only (without ping, 0-65535)\n\t3. TCP Scan Plus Service Based Script Scan\n\t4. UDP Scan\n\t5. Vuln Script Scan\n\t6. Simple Scan\n\t7. Exit\n\n"+colors.END+colors.GREEN+"\n\nScan Type : "+colors.END)
            if xx == '1':
                full_tcp_scan(ip_addr, batch)
                udp_scan(ip_addr, batch)
                vuln_scan(ip_addr, batch)
                break
            elif xx == '2':
                full_tcp_scan(ip_addr, batch)
                break
            elif xx == '3':
                # TCP Plus NSE Scan
                full_tcp_scan(ip_addr, batch)
                cc = input("\nEnter File Name : ")
                p = 1
                service_groups = xml_processing(cc, p)
                ip_addr = ''
                batch = ''
                if service_groups is not None:
                    service_nse_scan(ip_addr, batch, service_groups)
            elif xx == '4':
                udp_scan(ip_addr, batch)
                break
            elif xx == '5':
                vuln_scan(ip_addr, batch)
                break
            elif xx == '6':
                simple_scan(ip_addr, batch)
                break
            elif xx == '7':
                print("Exiting... :(")
                sys.exit(0)
            else:
                print(colors.RED+"' Wrong Input Observed!! Please correct"+colors.END)
            continueflag = 0

        except nmap.PortScannerError:
            print(colors.RED+"Nmap Not Installed"+colors.END, sys.exc_info[0])
            sys.exit(0)
        except:
            print(colors.YELLOW+"\n\t\tError!!  BYE!!"+colors.END)
            sys.exit(0)

    return batch



print(colors.YELLOW+"Loading ▂▃▅▇█▓▒░"+colors.END)
time.sleep(2)
print(colors.RED+"\n")
print(" ▐ ▄ • ▌ ▄ ·.  ▄▄▄·  ▄▄▄·     ▄▄▄· ▄• ▄▌▄▄▄▄▄           ▐ ▄ .▄▄ · ▄▄▄ .")
print("•█▌▐█·██ ▐███▪▐█ ▀█ ▐█ ▄█    ▐█ ▀█ █▪██▌•██  ▪         •█▌▐█▐█ ▀. ▀▄.▀·")
print("▐█▐▐▌▐█ ▌▐▌▐█·▄█▀▀█  ██▀·    ▄█▀▀█ █▌▐█▌ ▐█.▪ ▄█▀▄     ▐█▐▐▌▄▀▀▀█▄▐▀▀▪▄")
print("██▐█▌██ ██▌▐█▌▐█ ▪▐▌▐█▪·•    ▐█ ▪▐▌▐█▄█▌ ▐█▌·▐█▌.▐▌    ██▐█▌▐█▄▪▐█▐█▄▄▌")
print("▀▀ █▪▀▀  █▪▀▀▀ ▀  ▀ .▀        ▀  ▀  ▀▀▀  ▀▀▀  ▀█▄▀▪    ▀▀ █▪ ▀▀▀▀  ▀▀▀ "+colors.END)                                                                                                                                                                                                                                                                                                                                                                     
print(colors.GREEN+"\n\t\t\t\t\t\t\t\t\t┌∩┐(◣_◢)┌∩┐\n\t\t\t\t\t\t\t\t\t @0xd3X73r"+colors.END)                                                                                                                                 
time.sleep(2)                                                                                                                                 
                                                                                                                                 

mode = input(colors.YELLOW+"Select Mode : \n\n\t1. Scan Automator\n\t2. Import .xml nmap output for NSE scanning\n\n"+colors.END+colors.GREEN+"Mode : "+colors.END)
if mode == '1':
    yes_read_file = input(colors.YELLOW+"Do you want to read from a file? Press y to read from a file!!\t"+colors.END)
    if yes_read_file == 'y' or yes_read_file == 'Y':
        ip_final = ''
        ip_addr = ''
        file_path = input(colors.YELLOW+"\nPlease specify the full path of the file that needs to be read!!\n"+colors.END)
        regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                    25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''
        if os.path.exists(file_path):
            ip_address = open(file_path, 'r').read().split('\n')
            for ip_add in ip_address:
                if not ip_add == '0.0.0.0':
                    if re.search(regex, ip_add):
                        ip_final = ip_final + ' ' + ip_add
                    else:
                        try:
                            ip_soc = socket.gethostbyname(ip_add)
                            ip_final = ip_final + ' ' + ip_soc
                        except:
                            print(ip_add + " is not correctly formatted!!")

        ip_addr = ip_final.replace('0.0.0.0','').replace('1.0.0.1','')
        if not ip_addr == '':
            print(colors.BLUE+ip_addr)
            continueflag = 0
            batch = scan(ip_addr, continueflag)
            cc = batch
            p = 0
            print(colors.BLUE+"\n\t\t\tXML Processing.....>"+colors.END)
            service_groups = xml_processing(cc, p)
            if service_groups is not None:
                service_nse_scan(ip_addr, batch, service_groups)

        else:
            print("Nothing to Scan!!")


    else:
        ip_addr = '0.0.0.0'
        ip_final = ''
        ip_finally = ''
        while ip_addr == '0.0.0.0':
            ip_addr = input(colors.YELLOW+"\nPlease enter the IP address or hostname you want to scan: "+colors.END)
            regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
                                25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)'''
            ip_address = ip_addr.split(' ')
            for ip_add in ip_address:
                if re.search(regex, ip_add):
                    ip_final = ip_final + ' ' + ip_add
                else:
                    try:
                        ip_soc = socket.gethostbyname(ip_add)
                        ip_final = ip_final + ' ' + ip_soc
                    except:
                        print(ip_add + " is not correctly formatted!!")

        ip_finally = ip_final.replace('0.0.0.0','').replace('1.0.0.1','')
        if not ip_finally == '':
            batch = scan_ip(ip_finally, 0)
            cc = "IP1"
            p = 0
            print("\n\t\t\tXML Processing.....>")
            service_groups = xml_processing(cc, p)
            if service_groups is not None:
                service_nse_scan(ip_addr, batch, service_groups)

        else:
            print("Nothing to Scan!!")
elif mode == '2':
    # .xml file import cheyyunnathanenkil ivudunnu thudangunnu
    cc = input(colors.YELLOW+"\nEnter File Name : "+colors.END)
    p = 1
    service_groups = xml_processing(cc, p)
    ip_addr = ''
    batch = ''
    if service_groups is not None:
        service_nse_scan(ip_addr, batch, service_groups)

else:
    print(colors.RED+"Wrong Mode....>\n\t\t\tExiting :("+colors.END)
    sys.exit(0)