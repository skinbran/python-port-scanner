# python-port-scanner

This is a port scanner that utilizes python and different packages within python to scan ports of a desired target host/ipaddress. Options are available to conduct a TCP or UDP scan, traceroute, ping, and also to export the results of the scan to a pdf file. By default, the scanner will scan TCP, however UDP can be selected by using the flag `u` or `--udp`.

Required:
> Python 3.6 <br>
> fpdf

Sample script calls:
 > `python IT567_Python_Script.py -t 192.168.0.1` <br>
 > `python IT567_Python_Script.py -t 192.168.0.1 -p 21 22 -e`

Flags available:

  > -t : --target <br>
  Used to specify the target of the scan. Can be a single IP address, IP address range, or a subnet.
  >> ex. `-t 192.168.0.1` <br>
  >> ex. `-t 192.168.0.1 192.168.0.238` <br>
  >> ex. `-t 192.168.200.0/24`
  
 > -p : --port <br>
  > Used to specify which port to scan. If not specified then ports 0 - 1025 will be scanned. Can specify 1 or more ports.
  >> ex. `-p 21 22 23`
  
 > -u : --udp <br>
 flag to indicate to scan only the udp ports of the target.
 
 > -e : --export <br>
 flag to export the output of the scan to a PDF file. File will be exported to the same directory as the script.
 
 > -r : --traceroute <br>
 flag to trace the route from local machine to target address. Utlizes the system process for traceroute.
 
 > -x : --ping <br>
 flag to ping the target address or range of addresses.
 

 
 
