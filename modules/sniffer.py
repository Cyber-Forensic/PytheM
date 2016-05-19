#!/usr/bin/env python2.7
#coding=UTF-8

# Copyright (c) 2016 m4n3dw0lf
#
# Este arquivo é parte do programa PytheM

# PytheM é um software livre; você pode redistribuí-lo e/ou 
# modificá-lo dentro dos termos da Licença Pública Geral GNU como 
# publicada pela Fundação do Software Livre (FSF); na versão 3 da 
# Licença, ou (na sua opinião) qualquer versão.

# Este programa é distribuído na esperança de que possa ser  útil, 
# mas SEM NENHUMA GARANTIA; sem uma garantia implícita de ADEQUAÇÃO
# a qualquer MERCADO ou APLICAÇÃO EM PARTICULAR. Veja a
# Licença Pública Geral GNU para maiores detalhes.

# Você deve ter recebido uma cópia da Licença Pública Geral GNU junto
# com este programa, Se não, veja <http://www.gnu.org/licenses/>.


from scapy.all import *
from scapy.error import Scapy_Exception
from modules.utils import *
from datetime import datetime

class Sniffer(object):



	def __init__(self, interface, filter):
		self.interface = interface
		self.filter = filter
		if self.filter == 'manual':
			print "[?] Utilizar o filtro no formato do tcpdump ex: 'host 192.168.0.1 and port 80'"
			self.filt = raw_input("[+] Informe o filtro: ")
			print "[+] Sniffer com o filtro: '{}' inicializado.".format(self.filt)
		self.wrpcap = raw_input("[*] Deseja gravar o resultado em arquivo .pcap no diretório atual?[s/n]: ")

	def All(self, p):
		print p
		print

	def DNSsniff(self, p):
		if IP in p:
			ip_src= p[IP].src
			ip_dst = p[IP].dst
			if p.haslayer(DNS) and p.getlayer(DNS).qr == 0:
				print str(ip_src) + " --> " + str(ip_dst) + " : " + "(" + p.getlayer(DNS).qd.qname + ")"

	def HTTPsniff(self, p):
		if IP in p:
			ip_src = p[IP].src
			ip_dst = p[IP].dst
			if p.haslayer(TCP) and p.getlayer(TCP).dport == 80 and p.haslayer(Raw):
				print str(ip_src) + " --> " + str(ip_dst) + "\n" + p.getlayer(Raw).load


	def MANUALsniff(self, p):
		if IP in p:
			ip_src = p[IP].src
			ip_dst = p[IP].dst
			if p.haslayer(Raw):
				print str(ip_src) + " --> " + str(ip_dst) + "\n" + p.getlayer(Raw).load

	def start(self):
                if self.filter == 'http' and self.wrpcap == 's':
			try:
				print "[+] Sniffer HTTP inicializado"
				p = sniff(iface=self.interface,filter = "port 80", prn = self.HTTPsniff)
                        	time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
				wrpcap("pythem{}.pcap".format(time),p)
			
			except KeyboardInterrupt:
				print "\n[!] Finalizado pelo usuário."


		elif self.filter == 'dns' and self.wrpcap == 's':
			try:
				print "[+] Sniffer DNS inicializado"
       	                	p = sniff(iface=self.interface, filter = "port 53", prn = self.DNSsniff)
                        	time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
				wrpcap("pythem{}.pcap".format(time),p)

			except KeyboardInterrupt:
				print "\n[!] Finalizado pelo usuário."

		elif self.filter == 'manual' and self.wrpcap == 's':
			try:
				p = sniff(iface=self.interface, filter ="{}".format(self.filt), prn=self.MANUALsniff)
                        	time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
				wrpcap("pythem{}.pcap".format(time),p)
			except KeyboardInterrupt:
				print "\n[!] Finalizado pelo usuário."


		elif self.filter == 'all' and self.wrpcap == 's':
			try:
				p = sniff(iface=self.interface, prn=self.All)
				time = datetime.now().strftime('%Y-%m-%d_%H:%M:%S')
				wrpcap("pythem{}.pcap".format(time),p)
			except KeyboardInterrupt:
				print "\n[!] Finalizado pelo usuário."

		elif self.filter == 'all' and self.wrpcap != 's':
			print "[+] Sniffer Global inicializado"
			p = sniff(iface=self.interface, prn=self.All)
			print "\n[!] Finalizado pelo usuário."

                elif self.filter == 'http' and self.wrpcap != 's':
                        print "[+] Sniffer HTTP inicializado"
                        p = sniff(iface=self.interface,filter ="port 80",prn = self.HTTPsniff, store = 0)
                        print "\n[!] Finalizado pelo usuário."


                elif self.filter == 'dns' and self.wrpcap != 's':
                        print "[+] Sniffer DNS inicializado"
                        p = sniff(iface=self.interface, filter = "port 53", prn = self.DNSsniff, store = 0)
                        print "\n[!] Finalizado pelo usuário."


                elif self.filter == 'manual' and self.wrpcap != 's':
                        p = sniff(iface=self.interface, filter ="{}".format(self.filt), prn=self.MANUALsniff, store = 0)
                        print "\n[!] Finalizado pelo usuário."

