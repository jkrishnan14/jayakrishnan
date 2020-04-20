Port scan

Purpose
Sometimes firewalls are tough and you need the most basic stupid portscanner there is to just test for open ports.

Features
Can scan single IPs and single ports Example: portscanner.py 192.168.0.1 22
Can parse CIDR range and scan multiple ips Example: portscanner.py 192.168.0.1/24 22
Can parse port ranges and scan multiple ports Example: portscanner.py 192.168.0.1 1-1024
Any combiniation of the above 3
TODO:
Add the option to parse a list of ports i.e. portscanner.py <IP> 22, 23, 445
Add the option to parse a list of IPs i.e. portscanner.py 192.168.0.1, 192.168.0.2, 192.168.0.3 <port(s)>
Add timeout flag to change the length of timeouts between scans
Usage:
python3 portscanner.py <IP> <port>
Example: python3 portscanner.py 192.168.0.1/24 1-1024

Reference :https://github.com/3ndG4me/Simple-Port-Scanner/blob/master

 Network sniffer

Sniffer
A network sniffer written in python

Installing / Getting started
Sniffer needs python3

python sniffer.py
Features
Windows and linux support
Saving captured packages to pcap file
Configuration
A packet sniffer. Collect packets until ctrl+c pressed or after -t seconds

optional arguments:
  -h, --help            show this help message and exit
  -f FILENAME, --filename FILENAME
                        pcap file name (don't give extension)
  -nr, --noraw          No Raw mode, Stops printing raw packets
  -t TIME, --time TIME  Capture time in second

reference https://github.com/Rassilion/sniffer

3. Password cracking using Johny

John the Ripper (JtR) is one of the hacking tools the Varonis IR Team used in the first Live Cyber Attack demo, and one of the most popular password cracking programs out there.
Requeriments
pip install python-gnupg
pip install python-magic

4. Network 
