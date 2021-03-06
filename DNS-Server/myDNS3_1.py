#! /usr/bin/env python
'''
Created on Dec 9, 2011

@author: Tobias Endres, Frieder Paape
'''

import threading, socket
from scapy.all import sniff, send, IP, UDP, DNS, DNSRR, UDPerror

fakedns_ip = "10.10.42.12"
dns_ttl = 10000

localhost = "192.168.169.138"#"172.0.0.1"
listenall = False

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
            if dns.qd != None and dns_id != dns.id and (ip.src != localhost or listenall==True):
                
                dns_id = dns.id
                #authoritive answer only (aa=1)
                answer = IP(dst=ip.src,src=ip.dst)/UDP(dport=ip.sport,sport=ip.dport)/DNS(id=dns.id,qr=1,aa=1,qd=dns.qd,an=DNSRR(rrname=dns.qd.qname, ttl=dns_ttl, rdata=fakedns_ip))
                #nscount=1// gibt nur an, das der ns ein authoritve ist, rd=1 recursion desired, ra=1 recursion available, 
                #answer authenticated bit set:
                answer = IP(dst=ip.src,src=ip.dst)/UDP(dport=ip.sport,sport=ip.dport)/DNS(id=dns.id,qr=1,aa=1,z=2,qd=dns.qd,an=DNSRR(rrname=dns.qd.qname, ttl=dns_ttl, rdata=fakedns_ip))

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


# auszug aus scapy/layers/dns.py:
#
#    fields_desc = [ ShortField("id",0),
#                    BitField("qr",0, 1),
#                    BitEnumField("opcode", 0, 4, {0:"QUERY",1:"IQUERY",2:"STATUS"}),
#                    BitField("aa", 0, 1),
#                    BitField("tc", 0, 1),
#                    BitField("rd", 0, 1),
#                    BitField("ra", 0 ,1),
#                    BitField("z", 0, 3),
#                    BitEnumField("rcode", 0, 4, {0:"ok", 1:"format-error", 2:"server-failure", 3:"name-error", 4:"not-implemented", 5:"refused"}),
#                    DNSRRCountField("qdcount", None, "qd"),
#                    DNSRRCountField("ancount", None, "an"),
#                    DNSRRCountField("nscount", None, "ns"),
#                    DNSRRCountField("arcount", None, "ar"),
#                    DNSQRField("qd", "qdcount"),
#                    DNSRRField("an", "ancount"),
#                    DNSRRField("ns", "nscount"),
#                    DNSRRField("ar", "arcount",0) ]