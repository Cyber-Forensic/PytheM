#!/usr/bin/env python2.7
#coding=UTF-8


from scapy.all import *
from scapy.error import Scapy_Exception
from modules.utils import *


class Sniffer(object):



	def __init__(self, interface, filter):

		self.interface = interface
		self.filter = filter


	def DNSsniff(self, p):
		if IP in p:
			ip_src= p[IP].src
			ip_dst = p[IP].dst
			if p.haslayer(DNS) and p.getlayer(DNS).qr == 0:
				print str(ip_src) + " --> " + str(ip_dst) + " : " + "(" + p.getlayer(DNS).qd.qname + ")"

	def HTTPsniff(self, p):
		for p.haslayer(TCP) and p.getlayer(TCP).dport == 80 and p.haslayer(Raw):
			print p.getlayer(Raw).load


        def start(self):
                if self.filter == 'http':
                        sniff(iface=self.interface,prn = self.HTTPsniff)
                        print "\n[!] Finalizado pelo usuário."




                elif self.filter == 'dns':
                        sniff(iface=self.interface, filter = "port 53", prn = self.DNSsniff, store = 0)
                        print "\n[!] Finalizado pelo usuário."



