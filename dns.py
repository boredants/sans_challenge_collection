#!/usr/bin/python
#Python script to parse a PCAP file and return DNS queries and the
#host that made them

import dpkt
import socket
import datetime

rrtype = {
1: 'A',
2: 'NS',
5: 'CNAME',
6: 'SOA',
10: 'NULL',
12: 'PTR',
13: 'HINFO',
15: 'MX',
16: 'TXT',
28: 'AAAA',
33: 'SRV',
41: 'OPT',
}

filename = raw_input('Type filename of pcap file: ')

f = open(filename, 'rb')
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
    #Check for IPv4 traffic
    try:
        eth = dpkt.ethernet.Ethernet(buf)
    except:
        continue
    if eth.type != 2048:
        continue
    #Check for UDP
    try:
        ip = eth.data
    except:
        continue
    if ip.p != 17:
        continue
    #Filter DNS traffic on standard port
    try:
        udp = ip.data
    except:
        continue
    if udp.sport != 53 and udp.dport != 53:
        continue
    #Get IP address of host that made query
    ip_hdr = eth.data
    dst_addr = socket.inet_ntoa(ip_hdr.dst)

    #Get timestamp of each packet
    tstamp = str(datetime.datetime.utcfromtimestamp(ts))

    #Make the dns object out of the udp data and
    #Check for it being a Resource Record (answer) and for opcode QUERY
    try:
        dns = dpkt.dns.DNS(udp.data)
    except:
        continue
    if dns.qr != dpkt.dns.DNS_R:
        continue
    if dns.opcode != dpkt.dns.DNS_QUERY:
        continue
    if dns.rcode != dpkt.dns.DNS_RCODE_NOERR:
        continue
    if len(dns.an) < 1:
        continue
    #process and print responses based on record type
    for answer in dns.an:
        if answer.type == 1: #A records
            for qname in dns.qd:
                print tstamp + " ----- " + dst_addr + " ----> " + qname.name + " ----- " + str(rrtype[answer.type])
