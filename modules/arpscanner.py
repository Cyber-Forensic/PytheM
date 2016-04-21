#!/usr/bin/env python2.7
#coding=UTF-8

import argparse
import sys
import os
from scapy.all import srp,Ether,ARP,conf


class ARPscanner(object):


	def __init__(self, range, interface):

		desc = 'Scaneia um Endereço/Range de IP'
		self.range = range
		self.interface = interface


	def scan(self):
		try:
			
			print "\n[+] Scaneando... "
			conf.verb = 0
			ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.range), timeout = 2, iface=self.interface, inter=0.1)
			for snd,rcv in ans:
				print rcv.sprintf(r"MAC: %Ether.src% - IP: %ARP.psrc%")
				
		except KeyboardInterrupt:
			print "[*] Finalizado pelo usuário."
			sys.exit(1)
