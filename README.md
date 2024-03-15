# nmap_Auto_NSE+
Automating nmap scans with service-based NSE (Nmap Script Engine) scanning functionality

A tool for Automating Infrastructure Vunlerabiltiy Assessment with automating nmap enumeration with service based NSE (Nmap Script Engine) script scans according to each service that identified from scan. 

Also you can import nmap output (.xml file) and it will initiate service-based NSE script scans for each service.


It is an interactive tool. 

You can give IPs for scanning as txt file or single IP, and it will do a full port tcp scan, udp scan, and script vuln scan. After the tcp scan, the tool will fetch the details from the nmap output.xml file and initiate service-based script scans as per each service detected on ips. 

It will save all scan output to the same location. 


If you already have an nmap .xml output file, then you can directly initiate service-based NSE scans (for this, you may need to select Mode 2).


Every scans output will be save on the same directory. And the output name will like below:

Output names, if batch :
	
 	1. Tcp scan output will be save as - <batch_number>tcp.xml, <batch_number>tcp.nmap, <batch_number>tcp.gnmap
	
 	2. Udp scan output will be save as - <batch_number>udp.xml, <batch_number>udp.nmap, <batch_number>udp.gnamp
	
 	3. Vuln scan output will be save as - <batch_number>vuln.xml, <batch_number>vuln.nmap, <batch_number>vuln.gnamp
	
 	4. Simple scan output will be save as - <batch_number>simple.xml, <batch_number>simple.nmap, <batch_number>simple.gnamp
	
 	5. Service based scan output will be save as - <batch_number><service_name>NSE.xml, <batch_number><service_name>NSE.nmap, <batch_number><service_name>NSE.gnamp

Output names, if single ip :
	
 	1. Tcp scan output will be save as - IP1tcp.xml, IP1tcp.nmap, IP1tcp.gnmap
	2. Udp scan output will be save as - IP1udp.xml, IP1udp.nmap, IP1udp.gnamp
	3. Vuln scan output will be save as - IP1vuln.xml, IP1vuln.nmap, IP1vuln.gnamp
	4. Simple scan output will be save as - IP1simple.xml, IP1simple.nmap, IP1simple.gnamp
	5. Service based scan output will be save as - IP1<service_name>NSE.xml, IP1<service_name>NSE.nmap, IP1<service_name>NSE.gnamp

Output names, if you were input .xml file,
	
 	1. Service scan output will be save as - <batch_number><service_name>NSE.xml, <batch_number><service_name>NSE.nmap, <batch_number><service_name>NSE.gnamp
	(If you are import .xml file, at that time it will prompt you to provide batch number)


#Scan Types
----------
1. All ------------------------------------->  Full port tcp scan without ping, udp scan, script vuln scan and service based script scan
2. TCP Scan (without ping, 0-65535)--------->  Full port tcp scan without ping.
3. TCP scan With Service Based Script Scan-->  Full prt tcp scan without ping.
4. UDP Scan--------------------------------->  Top 1000 ports udp scan.
5. Vuln Script Scan------------------------->  Nmap NSE script vuln scan.
6. Simple Scan------------------------------>  Simple tcp scan without ping. (nmap -sV -v -Pn -T4 -oA <batch_number>simple <ip>)


#USAGE
-----
pyhon nmap_Auto_NSE+.py
