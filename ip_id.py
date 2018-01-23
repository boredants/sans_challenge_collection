import dpkt
import datetime
file = raw_input("Enter full path to pcap file: ")
f = open(file)
pcap = dpkt.pcap.Reader(f)

for ts, buf in pcap:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        tcp = ip.data
        print str(datetime.datetime.utcfromtimestamp(ts))+"----"+ str(ip.id)
    

