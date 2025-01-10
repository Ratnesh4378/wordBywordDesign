#!/usr/bin/python3
from scapy.all import *

payload = "UserId:123,ProductID:1234567890,PPPP:4324,ProductID:1234567890,PPPP:4324,ProDuctID:1234567890,"
payload += "a"*500
# payload = 'a'*798 + "she" + 'b'*1 + 'hi'
payload += 'c' * (1400 - len(payload))
pkt = Ether(src="3c:fd:fe:9e:7b:5c", dst="3c:fd:fe:9e:7b:85",type=0x0800)
pkt = pkt/IP(src="192.168.1.1", dst="192.168.1.2", id = 0xffff)
pkt = pkt/TCP(sport=5000, dport=56784, options=[('NOP',0),('NOP',0),('Timestamp', (1098453, 0))])
pkt = pkt/payload

wrpcap("query1_3.pcap",pkt)