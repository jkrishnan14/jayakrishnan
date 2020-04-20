import socket
import subprocess
import sys
import os
from datetime import datetime
import struct
import textwrap
import scapy.all as scapy
import argparse
import prettytable
from prettytable import PrettyTable
from scapy.layers import http
import threading
from threading import Thread
import time
from bs4 import BeautifulSoup
import requests
import requests.exceptions
import urllib3
from urllib.parse import urlsplit
from collections import deque
import re
import argparse
#from pexpect import pxssh
import nmap




os.system("clear")
print("Tool started")
print('\n')

print(" 1. Port Scanning ")
print(" 2. Network Sniffer ")
print(" 3. Password cracking ")
print(" 4. Email/Phone/Banner")
print(" 5. Vunerability Scanner")
print(" 6. Running Service ")


op = input("Choose your desired Option : ")

#First case

#reference from https://github.com/3ndG4me/Simple-Port-Scanner/blob/master/portscanner.py 

if op == "1" :
#!/usr/bin/python3

import socket
from netaddr import IPNetwork
import sys


if len(sys.argv) < 3:
    print("Usage: portscanner.py <IP or IP Range> <port or port range>")
    print("Example: portscannery.py 192.168.2.3 1-1024")
else:
    port = sys.argv[2]
    port = port.replace('-', ' ').split(' ')
    if (len(port) > 1):
        range_start = int(port[0])
        range_end = int(port[1]) + 1
        port_range = range(range_start, range_end)
    else:
        range_start = int(port[0])
        range_end = int(port[0]) + 1
        port_range = range(range_start, range_end)
    
    
    for ip in IPNetwork(sys.argv[1]):
        for port in port_range:
            s = socket.socket()
            s.settimeout(1) # Speeds things up, change this to a higher value if you're on a slower connection.
            try:
                s.connect((str(ip), port))
                print("Port %d is open on %s" % (port, str(ip)))
                s.close()
            except Exception as e:
                print("Port %d not open on %s" % (port, str(ip)))
                s.close()#second case
# reference with subscription for packpub  "https://subscription.packtpub.com/book/networking_and_servers/9781784399771/7/ch07lvl1sec43/pyshark"

#Second case

elif op == "2":

#reference from https://github.com/Rassilion/sniffer/blob/master/sniffer.py 
          
  import socket, sys, time, argparse
from struct import *


class Sniffer:
    def __init__(self):
        # argument parser for console arguments
        parser = argparse.ArgumentParser(
            description='A packet sniffer. Collect packets until ctrl+c pressed or after -t seconds ')
        # optimal arguments
        parser.add_argument("-f", "--filename", type=str, help="pcap file name (don't give extension)",
                            default='capture')
        parser.add_argument("-nr", "--noraw", action='store_false', default=True,
                            help="No Raw mode, Stops printing raw packets")
        parser.add_argument("-t", "--time", type=int, default=0, help="Capture time in second")
        # store pares arguments
        self.args = parser.parse_args()
        # initialize stat variables
        self.start_time = time.time()
        self.ip = False
        self.packet_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        # try capture all packets(linux) if not, capture ip packets(windows)
        # windows doesnt support socket.AF_PACKET so fallback to ip packets
        try:
            # create raw packet socket
            self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
        except AttributeError:
            # set ip mode true
            self.ip = True
            # get the public network interface
            HOST = socket.gethostbyname(socket.gethostname())

            # create a raw utp socket and bind it to the public interface
            self.s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.s.bind((HOST, 0))

            # Include IP headers
            self.s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # receive all packages
            self.s.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        except socket.error as e:
            print('Socket could not be created.')
            print('    Error Code : {}'.format(getattr(e, 'errno', '?')))
            print('       Message : {}'.format(e))
            sys.exit()

    # starts capture loop, saves to pcap file and displays packet detail
    def capture_packets(self):
        while True:
            # Receive data from the socket, return value is a pair (bytes, address)
            # max buffer size for packets
            packet = self.s.recvfrom(65565)

            # packet string from tuple
            packet = packet[0]

            print("-------------Packet Start-------------")
            # print raw packet if noraw not given
            if self.args.noraw:
                print('Packet: {}'.format(str(packet)))

            # add packet to pcap file
            self.add_pcap(packet)

            # check if using ip mode or ethernet mode
            if self.ip is not True:
                # parse ethernet header
                eth_length = 14
                # get first 14(eth_length) character from packet
                eth_header = packet[0:eth_length]
                # unpack string big-endian to (6 char, 6 char, unsigned short) format
                eth = unpack('!6s6sH', eth_header)
                # get eth_protocol from unpacked data
                eth_protocol = socket.ntohs(eth[2])
                # create info
                addrinfo = [
                    'Destination MAC: {}'.format(self.mac_addr(packet[0:6])),
                    'Source MAC: {}'.format(self.mac_addr(packet[6:12])),
                    'Protocol: {}'.format(eth_protocol)
                ]
                print('---' + ' '.join(addrinfo))
                # remove ethernet header to parse ip header
                packet = packet[14:]

            self.packet_count += 1

            # take first 20 characters for the ip header
            ip_header = packet[0:20]
            # unpack string big-endian to
            # (skip 8 byte unsigned char(8bit),unsigned char(8bit),skip 2 byte 4 char, 4 char)
            iph = unpack('! 8x B B 2x 4s 4s', ip_header)
            # version and ihl is first 8bit so a char
            version_ihl = packet[0]
            # shift 4 bit right to get version
            version = version_ihl >> 4
            # mask 4 bit to get ihl
            ihl = version_ihl & 0xF
            # calculate header length
            iph_length = ihl * 4
            # get ttl integer
            ttl = iph[0]
            # get protocol integer
            protocol = iph[1]
            # get ip bytes and convert to host byte order
            s_addr = socket.inet_ntoa(iph[2])
            d_addr = socket.inet_ntoa(iph[3])

            headerinfo = [
                'Version: {}'.format(version),
                'IP Header Length: {}'.format(ihl),
                'TTL: {}'.format(ttl),
                'Protocol: {}'.format(protocol),
                'Source Addr: {}'.format(s_addr),
                'Destination Addr: {}'.format(d_addr)]

            # TCP protocol
            if protocol == 6:
                print('---' + ' '.join(headerinfo))
                t = iph_length
                # get 20 characters after ip header
                tcp_header = packet[t:t + 20]

                # unpack string in tcp header format
                tcph = unpack('!HHLLBBHHH', tcp_header)
                self.tcp_count += 1

                source_port = tcph[0]
                dest_port = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                # shift 4 bits to get length
                tcph_length = doff_reserved >> 4
                # create info
                tcpinfo = [
                    'TCP PACKET',
                    'Source Port: {}'.format(source_port),
                    'Destination Port: {}'.format(dest_port),
                    'Sequence Num: {}'.format(sequence),
                    'Acknowledgement: {}'.format(acknowledgement),
                    'TCP Header Len.: {}'.format(tcph_length),
                ]
                print('---' + ' '.join(tcpinfo))
                # calculate total header size
                h_size = iph_length + tcph_length * 4

                # get data from the packet
                data = packet[h_size:]
                # try to decode plain text data or print hex
                try:
                    print('Data: {}'.format(data.decode('ascii')))
                except:
                    print('Data: {}'.format(str(data)))
            # UDP protocol
            elif protocol == 17:
                print('---' + ' '.join(headerinfo))
                u = iph_length
                udph_length = 8
                # get after 8 character from ip header
                udp_header = packet[u:u + 8]

                # unpack to 4 2bytes
                udph = unpack('!HHHH', udp_header)
                self.udp_count += 1

                source_port = udph[0]
                dest_port = udph[1]
                length = udph[2]
                checksum = udph[3]

                udpinfo = [
                    'UDP PACKET',
                    'Source Port: {}'.format(source_port),
                    'Destination Port: {}'.format(dest_port),
                    'Length: {}'.format(length),
                    'Checksum: {}'.format(checksum)
                ]
                print('---' + ' '.join(udpinfo))

                h_size = iph_length + udph_length

                # get data from the packet

                data = packet[h_size:]

                print('Data: {}'.format(str(data)))
            print("-------------Packet End-------------")
            self.control_time()

    # beatify mac addresses
    def mac_addr(self, a):
        # split address to 6 character
        pieces = (a[i] for i in range(6))
        # format to 00:00:00:00:00:00
        return '{:2x}:{:2x}:{:2x}:{:2x}:{:2x}:{:2x}'.format(*pieces)

    def control_time(self):
        if self.args.time > 0 and ((time.time() - self.start_time) > self.args.time):
            self.exit()
            sys.exit(1)

    def print_stats(self):
        stats = [
            'Captured packets: {}'.format(self.packet_count),
            'TCP Packets: {}'.format(self.tcp_count),
            'UDP Packets: {}'.format(self.udp_count),
            'Total Time: {}'.format(time.time() - self.start_time)
        ]
        print('---' + ' '.join(stats))

    def run(self):
        try:
            # open pcap if ip mode enabled link_type is 101, else 1(ethernet)
            self.open_pcap(self.args.filename + '.pcap', (101 if self.ip else 1))
            # start capturing
            self.capture_packets()
        except KeyboardInterrupt:  # exit on ctrl+c
            self.exit()

    def exit(self):
        # close file
        self.close_pcap()
        # print accumulated stats to screen
        self.print_stats()

    def open_pcap(self, filename, link_type=1):
        # open given filename write mode in binary
        self.pcap_file = open(filename, 'wb')
        # create pcap header and write file
        # header format (https://wiki.wireshark.org/Development/LibpcapFileFormat#Global_Header)
        # (magic_number,version_major,version_minor,thiszone,sigfigs,snaplen,network)
        # python representation
        # (unsigned int(1byte),unsigned short(2byte),unsigned short(2byte),int(4byte),unsigned int(1byte),unsigned int(1byte),unsigned int(1byte))
        self.pcap_file.write(pack('@ I H H i I I I', 0xa1b2c3d4, 2, 4, 0, 0, 65535, link_type))

    def add_pcap(self, data):
        ts_sec, ts_usec = map(int, str(time.time()).split('.'))
        length = len(data)
        # packet header format (https://wiki.wireshark.org/Development/LibpcapFileFormat#Record_.28Packet.29_Header)
        # (ts_sec,ts_usec,incl_len,orig_len)
        # python representation
        # (unsigned int(1byte),unsigned int(1byte),unsigned int(1byte),unsigned int(1byte))
        self.pcap_file.write(pack('@ I I I I', ts_sec, ts_usec, length, length))
        self.pcap_file.write(data)

    def close_pcap(self):
        # close file
        self.pcap_file.close()


if __name__ == '__main__':
    app = Sniffer()
    app.run()

#Third case

#reference from https://github.com/koboi137/john/blob/bionic/apex2john.py
    
    
elif op == "3" :
    import sys

def process_file(filename):
    with open(filename, "r") as f:
        for line in f.readlines():
            data = line.split(',')

            try:
                username, apexhash, sgid = data
            except:
                continue

            username = username.rstrip().lstrip()
            apexhash = apexhash.rstrip().lstrip()
            sgid = sgid.rstrip().lstrip()

            sys.stdout.write("$dynamic_1$%s$%s\n" % (apexhash, sgid + username))

if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.stderr.write("Usage: %s <apex-hashes.txt file(s)>\n" % sys.argv[0])
        sys.exit(-1)

    for i in range(1, len(sys.argv)):
        process_file(sys.argv[i])

#Fourth case

#reference from https://gist.github.com/linwoodc3/e12a7fbebfa755e897697165875f8fdb
        
elif op == "4" :
    import re
import pytz
import datetime
import platform


###################################
# Third party imports
###################################

import requests
from newspaper import Article
from bs4 import BeautifulSoup
from readability.readability import Document as Paper
from requests.packages.urllib3.exceptions import InsecureRequestWarning


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)


done = {}


def textgetter(url):
    """Scrapes web news and returns the content
    Parameters
    ----------
    url : str
        web address to news report
    Returns 
    -------
    
    answer : dict
        Python dictionary with key/value pairs for:
            text (str) - Full text of article
            url (str) - url to article
            title (str) - extracted title of article
            author (str) - name of extracted author(s)
            base (str) - base url of where article was located
            provider (str) - string of the news provider from url
            published_date (str,isoformat) - extracted date of article
            top_image (str) - extracted url of the top image for article
    """
    global done
    TAGS = ['h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'h7', 'p', 'li']

    # regex for url check
    s = re.compile('(http://|https://)([A-Za-z0-9_\.-]+)')
    u = re.compile("(http://|https://)(www.)?(.*)(\.[A-Za-z0-9]{1,4})$")
    if s.search(url):
        site = u.search(s.search(url).group()).group(3)
    else:
        site = None
    answer = {}
    # check that its an url
    if s.search(url):
        if url in done.keys():
            yield done[url]
            pass
        try:
            # make a request to the url
            r = requests.get(url, verify=False, timeout=1)
        except:
            # if the url does not return data, set to empty values
            done[url] = "Unable to reach website."
            answer['author'] = None
            answer['base'] = s.search(url).group()
            answer['provider']=site
            answer['published_date']=None
            answer['text'] = "Unable to reach website."
            answer['title'] = None
            answer['top_image'] = None
            answer['url'] = url
            answer['keywords']=None
            answer['summary']=None
            yield answer
        # if url does not return successfully, set ot empty values
        if r.status_code != 200:
            done[url] = "Unable to reach website."
            answer['author'] = None
            answer['base'] = s.search(url).group()
            answer['provider']=site
            answer['published_date']=None
            answer['text'] = "Unable to reach website."
            answer['title'] = None
            answer['top_image'] = None
            answer['url'] = url
            answer['keywords']=None
            answer['summary']=None

        # test if length of url content is greater than 500, if so, fill data
        if len(r.content)>500:
            # set article url
            article = Article(url)
            # test for python version because of html different parameters
            if int(platform.python_version_tuple()[0])==3:
                article.download(input_html=r.content)
            elif int(platform.python_version_tuple()[0])==2:
                article.download(html=r.content)
            # parse the url
            article.parse()
            article.nlp()
            # if parse doesn't pull text fill the rest of the data
            if len(article.text) >= 200:
                answer['author'] = ", ".join(article.authors)
                answer['base'] = s.search(url).group()
                answer['provider']=site
                answer['published_date'] = article.publish_date
                answer['keywords']=article.keywords
                answer['summary']=article.summary
                # convert the data to isoformat; exception for naive date
                if isinstance(article.publish_date,datetime.datetime):
                    try:
                        answer['published_date']=article.publish_date.astimezone(pytz.utc).isoformat()
                    except:
                        answer['published_date']=article.publish_date.isoformat()
                

                answer['text'] = article.text
                answer['title'] = article.title
                answer['top_image'] = article.top_image
                answer['url'] = url
                
                

            # if previous didn't work, try another library
            else:
                doc = Paper(r.content)
                data = doc.summary()
                title = doc.title()
                soup = BeautifulSoup(data, 'lxml')
                newstext = " ".join([l.text for l in soup.find_all(TAGS)])

                # as we did above, pull text if it's greater than 200 length
                if len(newstext) > 200:
                    answer['author'] = None
                    answer['base'] = s.search(url).group()
                    answer['provider']=site
                    answer['published_date']=None
                    answer['text'] = newstext
                    answer['title'] = title
                    answer['top_image'] = None
                    answer['url'] = url
                    answer['keywords']=None
                    answer['summary']=None
                # if nothing works above, use beautiful soup
                else:
                    newstext = " ".join([
                        l.text
                        for l in soup.find_all(
                            'div', class_='field-item even')
                    ])
                    done[url] = newstext
                    answer['author'] = None
                    answer['base'] = s.search(url).group()
                    answer['provider']=site
                    answer['published_date']=None
                    answer['text'] = newstext
                    answer['title'] = title
                    answer['top_image'] = None
                    answer['url'] = url
                    answer['keywords']=None
                    answer['summary']=None
        # if nothing works, fill with empty values
        else:
            answer['author'] = None
            answer['base'] = s.search(url).group()
            answer['provider']=site
            answer['published_date']=None
            answer['text'] = 'No text returned'
            answer['title'] = None
            answer['top_image'] = None
            answer['url'] = url
            answer['keywords']=None
            answer['summary']=None
            yield answer
        yield answer

    # the else clause to catch if invalid url passed in
    else:
        answer['author'] = None
        answer['base'] = s.search(url).group()
        answer['provider']=site
        answer['published_date']=None
        answer['text'] = 'This is not a proper url'
        answer['title'] = None
        answer['top_image'] = None
        answer['url'] = url
        answer['keywords']=None
        answer['summary']=None
        yield answer

#Fifth case

       #reference https://gist.github.com/kf4bzt/ff0b499821c12722341dbdbde3f57e60
elif op == "5" :

        x=PrettyTable(['Possible Vulnerabilites'])
        target_ip =input("Please enter target ip: ")
        arp_packet = scapy.ARP(pdst=ip)
        broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_broadcast_packet = broadcast_packet/arp_packet
        answered_list = scapy.srp(arp_broadcast_packet, timeout=1, verbose=False)[0]
        client_list = []

        for element in answered_list:
            client_dict = {"ip": element[1].psrc, "mac": element[1].hwsrc}
            client_list.append(client_dict) 
        x.add_row(client_list)
        print(x)
 

#Sixth case
elif op == "6" :
#reference 'https://github.com/Tib3rius/AutoRecon/blob/master/autorecon.py'
    def main():
       if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Network reconnaissance tool to port scan and automatically enumerate services found on multiple targets.')
    parser.add_argument('targets', action='store', help='IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.', nargs="*")
    parser.add_argument('-t', '--targets', action='store', type=str, default='', dest='target_file', help='Read targets from file.')
    parser.add_argument('-ct', '--concurrent-targets', action='store', metavar='<number>', type=int, default=5, help='The maximum number of target hosts to scan concurrently. Default: %(default)s')
    parser.add_argument('-cs', '--concurrent-scans', action='store', metavar='<number>', type=int, default=10, help='The maximum number of scans to perform per target host. Default: %(default)s')
    parser.add_argument('--profile', action='store', default='default', dest='profile_name', help='The port scanning profile to use (defined in port-scan-profiles.toml). Default: %(default)s')
    parser.add_argument('-o', '--output', action='store', default='results', dest='output_dir', help='The output directory for results. Default: %(default)s')
    parser.add_argument('--single-target', action='store_true', default=False, help='Only scan a single target. A directory named after the target will not be created. Instead, the directory structure will be created within the output directory. Default: false')
    parser.add_argument('--only-scans-dir', action='store_true', default=False, help='Only create the "scans" directory for results. Other directories (e.g. exploit, loot, report) will not be created. Default: false')
    parser.add_argument('--heartbeat', action='store', type=int, default=60, help='Specifies the heartbeat interval (in seconds) for task status messages. Default: %(default)s')
    nmap_group = parser.add_mutually_exclusive_group()
    nmap_group.add_argument('--nmap', action='store', default='-vv --reason -Pn', help='Override the {nmap_extra} variable in scans. Default: %(default)s')
    nmap_group.add_argument('--nmap-append', action='store', default='', help='Append to the default {nmap_extra} variable in scans.')
    parser.add_argument('-v', '--verbose', action='count', default=0, help='Enable verbose output. Repeat for more verbosity.')
    parser.add_argument('--disable-sanity-checks', action='store_true', default=False, help='Disable sanity checks that would otherwise prevent the scans from running. Default: false')
    parser.error = lambda s: fail(s[0].upper() + s[1:])
    args = parser.parse_args()

    single_target = args.single_target
    only_scans_dir = args.only_scans_dir

    errors = False

    if args.concurrent_targets <= 0:
        error('Argument -ch/--concurrent-targets: must be at least 1.')
        errors = True

    concurrent_scans = args.concurrent_scans

    if concurrent_scans <= 0:
        error('Argument -ct/--concurrent-scans: must be at least 1.')
        errors = True

    port_scan_profile = args.profile_name

    found_scan_profile = False
    for profile in port_scan_profiles_config:
        if profile == port_scan_profile:
            found_scan_profile = True
            for scan in port_scan_profiles_config[profile]:
                if 'service-detection' not in port_scan_profiles_config[profile][scan]:
                    error('The {profile}.{scan} scan does not have a defined service-detection section. Every scan must at least have a service-detection section defined with a command and a corresponding pattern that extracts the protocol (TCP/UDP), port, and service from the result.')
                    errors = True
                else:
                    if 'command' not in port_scan_profiles_config[profile][scan]['service-detection']:
                        error('The {profile}.{scan}.service-detection section does not have a command defined. Every service-detection section must have a command and a corresponding pattern that extracts the protocol (TCP/UDP), port, and service from the results.')
                        errors = True
                    else:
                        if '{ports}' in port_scan_profiles_config[profile][scan]['service-detection']['command'] and 'port-scan' not in port_scan_profiles_config[profile][scan]:
                            error('The {profile}.{scan}.service-detection command appears to reference a port list but there is no port-scan section defined in {profile}.{scan}. Define a port-scan section with a command and corresponding pattern that extracts port numbers from the result, or replace the reference with a static list of ports.')
                            errors = True

                    if 'pattern' not in port_scan_profiles_config[profile][scan]['service-detection']:
                        error('The {profile}.{scan}.service-detection section does not have a pattern defined. Every service-detection section must have a command and a corresponding pattern that extracts the protocol (TCP/UDP), port, and service from the results.')
                        errors = True
                    else:
                        if not all(x in port_scan_profiles_config[profile][scan]['service-detection']['pattern'] for x in ['(?P<port>', '(?P<protocol>', '(?P<service>']):
                            error('The {profile}.{scan}.service-detection pattern does not contain one or more of the following matching groups: port, protocol, service. Ensure that all three of these matching groups are defined and capture the relevant data, e.g. (?P<port>\d+)')
                            errors = True

                if 'port-scan' in port_scan_profiles_config[profile][scan]:
                    if 'command' not in port_scan_profiles_config[profile][scan]['port-scan']:
                        error('The {profile}.{scan}.port-scan section does not have a command defined. Every port-scan section must have a command and a corresponding pattern that extracts the port from the results.')
                        errors = True

                    if 'pattern' not in port_scan_profiles_config[profile][scan]['port-scan']:
                        error('The {profile}.{scan}.port-scan section does not have a pattern defined. Every port-scan section must have a command and a corresponding pattern that extracts the port from the results.')
                        errors = True
                    else:
                        if '(?P<port>' not in port_scan_profiles_config[profile][scan]['port-scan']['pattern']:
                            error('The {profile}.{scan}.port-scan pattern does not contain a port matching group. Ensure that the port matching group is defined and captures the relevant data, e.g. (?P<port>\d+)')
                            errors = True
            break

    if not found_scan_profile:
        error('Argument --profile: must reference a port scan profile defined in {port_scan_profiles_config_file}. No such profile found: {port_scan_profile}')
        errors = True

    heartbeat_interval = args.heartbeat

    nmap = args.nmap
    if args.nmap_append:
        nmap += " " + args.nmap_append

    outdir = args.output_dir
    srvname = ''
    verbose = args.verbose

    raw_targets = args.targets
    targets = []

    if len(args.target_file) > 0:
        if not os.path.isfile(args.target_file):
            error('The target file {args.target_file} was not found.')
            sys.exit(1)
        try:
            with open(args.target_file, 'r') as f:
                lines = f.read()
                for line in lines.splitlines():
                    line = line.strip()
                    if line.startswith('#') or len(line) == 0: continue
                    if line not in raw_targets:
                        raw_targets.append(line)
        except OSError:
            error('The target file {args.target_file} could not be read.')
            sys.exit(1)

    for target in raw_targets:
        try:
            ip = str(ipaddress.ip_address(target))

            if ip not in targets:
                targets.append(ip)
        except ValueError:

            try:
                target_range = ipaddress.ip_network(target, strict=False)
                if not args.disable_sanity_checks and target_range.num_addresses > 256:
                    error(target + ' contains ' + str(target_range.num_addresses) + ' addresses. Check that your CIDR notation is correct. If it is, re-run with the --disable-sanity-checks option to suppress this check.')
                    errors = True
                else:
                    for ip in target_range.hosts():
                        ip = str(ip)
                        if ip not in targets:
                            targets.append(ip)
            except ValueError:

                try:
                    ip = socket.gethostbyname(target)

                    if target not in targets:
                        targets.append(target)
                except socket.gaierror:
                    error(target + ' does not appear to be a valid IP address, IP range, or resolvable hostname.')
                    errors = True

    if len(targets) == 0:
        error('You must specify at least one target to scan!')
        errors = True

    if single_target and len(targets) != 1:
        error('You cannot provide more than one target when scanning in single-target mode.')
        sys.exit(1)

    if not args.disable_sanity_checks and len(targets) > 256:
        error('A total of ' + str(len(targets)) + ' targets would be scanned. If this is correct, re-run with the --disable-sanity-checks option to suppress this check.')
        errors = True

    if errors:
        sys.exit(1)

    with ProcessPoolExecutor(max_workers=args.concurrent_targets) as executor:
        start_time = time.time()
        futures = []

        for address in targets:
            target = Target(address)
            futures.append(executor.submit(scan_host, target, concurrent_scans))

        try:
            for future in as_completed(futures):
                future.result()
        except KeyboardInterrupt:
            for future in futures:
                future.cancel()
            executor.shutdown(wait=False)
            sys.exit(1)

        elapsed_time = calculate_elapsed_time(start_time)
        info('{bgreen}Finished scanning all targets in {elapsed_time}!{rst}')

else :
   print(" Enter a valid option... ")

