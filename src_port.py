import dpkt
import datetime
dstport = raw_input("Enter a destination port: ")
file = raw_input("Enter full path to pcap file: ")
f = open(file)
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        if tcp.dport == int(dstport):
                print str(datetime.datetime.utcfromtimestamp(ts))+"----"+ str(tcp.sport)
    

