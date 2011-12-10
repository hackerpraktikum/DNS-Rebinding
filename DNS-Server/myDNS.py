'''
Created on Dec 9, 2011

@author: Tobias Endres
'''
#! /usr/bin/env python

from scapy.all import sniff, DNS

def dns_callback(pkt):
    if DNS in pkt:
            #Hier noch eine sinnvolle Antwort erstellen
            return pkt.sprintf("DNS PAKET GEFUNDEN: %DNS.show%")
            
sniff( prn = dns_callback,  store=0)