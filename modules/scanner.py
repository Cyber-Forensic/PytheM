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
from netaddr import IPNetwork, IPRange, IPAddress, AddrFormatError
import random
import sys
import os

class Scanner(object):

	def __init__(self,target,interface,mode):
		self.interface = interface
		self.targets = target
		self.arprange = target
		self.range = self.get_range(target)
		self.portRange = []
		for i in range(0,65535):
			self.portRange.append(i)
		self.mode = mode
		self.portManual = []
	
	def get_range(self, targets):
                if targets is None:
                        return None

                try:
                        target_list = []
                        for target in targets.split(','):


                                if '/' in target:
                                        target_list.extend(list(IPNetwork(target)))

                                elif '-' in target:
                                        start_addr = IPAddress(target.split('-')[0])
                                        try:
                                                end_addr = IPAddress(target.split('-')[1])
                                                ip_range = IPRange(start_addr, end_addr)

                                        except AddrFormatError:
                                                end_addr = list(start_addr.words)
                                                end_addr[-1] = target.split('-')[1]
                                                end_addr = IPAddress('.'.join(map(str, end_addr)))
                                                ip_range = IPRange(start_addr, end_addr)



                                        target_list.extend(list(ip_range))

                                else:
                                        target_list.append(IPAddress(target))

                        return target_list

                except AddrFormatError:
                        sys.exit("[!]Especifique um Endereço/Range IP válido como alvo.")




	def portScan(self, hosts, ports):
		for dstPort in self.ports:
			srcPort = random.randint(1025,65534)
			resp = sr1(IP(dst=self.targetip)/TCP(sport=srcPort,dport=dstPort,flags="S"),timeout=1,verbose=0)
			if (str(type(resp)) == "<type 'NoneType'>"):
				print "[-]{}:{} está filtrada.".format(self.targetip,str(dstPort))
			elif(resp.haslayer(TCP)):
				if (resp.haslayer(TCP)):
					if(resp.getlayer(TCP).flags == 0x12):
						send_rst = sr(IP(dst=self.targetip)/TCP(sport=srcPort, dport=dstPort, flags="R"), timeout=1,verbose=0)
						print "[+]{}:{} está aberta.".format(self.targetip,str(dstPort))
			elif(resp.haslayer(ICMP)):
				if(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
					print "[-]{}:{} está filtrada.".format(self.targetip,str(dstPort))

	def MANUALscanner(self):
		
		liveCounter = 0
		self.portManual.append(input("[+] Informe a porta: "))
		self.ports = self.portManual
		print "\n[+] TCP Scan manual inicializado..."
		for target in self.range:
			self.targetip = str(target)
			resp = sr1(IP(dst=str(self.targetip))/ICMP(),timeout=2,verbose=0)
                        if (str(type(resp)) == "<type 'NoneType'>"):
                                print "\n[*]" + str(self.targetip) + " está desligado ou não respondendo.\n"
                        elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                                print "\n[*]" + str(self.targetip) + " está bloqueando ICMP.\n"
                        else:
                                print "\n[*]" + str(self.targetip) + " está online: "
                                self.portScan(str(self.targetip),self.portManual)
                                liveCounter += 1
          	print "De "+ str(len(self.range)) + " máquinas scaneadas, " + str(liveCounter) + " estão online."

		

        def TCPscanner(self):

		liveCounter = 0
                self.ports = self.portRange
		print "\n[+] TCP Scan inicializado..."
		for target in self.range:
	
			self.targetip = str(target)
                        resp = sr1(IP(dst=str(self.targetip))/ICMP(),timeout=2,verbose=0)
                        if (str(type(resp)) == "<type 'NoneType'>"):
                                 print "\n[*]" + str(self.targetip) + " está desligado ou não respondendo.\n"
                        elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                                 print "\n[*]" + str(self.targetip) + " está bloqueando ICMP.\n"
			else:
                                 print "\n[*]" + str(self.targetip) + " está online: "
	      			 self.portScan(str(self.targetip),self.portRange)
                                 liveCounter += 1
		print "De "+ str(len(self.range)) + " máquinas scaneadas, " + str(liveCounter) + " estão online."


	

	def ARPscanner(self):
                try:
	                print "\n[+] ARP Scan inicializado...\n"
         	        conf.verb = 0
                        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.arprange), timeout = 2, iface=self.interface, inter=0.1)
                        for snd,rcv in ans:
                                print rcv.sprintf(r"[+] IP: %ARP.psrc% tem o MAC: %Ether.src%")

                except KeyboardInterrupt:
                        print "\n[*] Finalizado pelo usuário."
                        sys.exit(1)



	def start(self):
		
		if self.mode == 'manual':
			try:
				self.MANUALscanner()
	                except KeyboardInterrupt:
        	                print "[*] Finalizado pelo usuário."
                	        os.system('kill %d' % os.getpid())
                	        sys.exit(1)
			
		elif self.mode == 'tcp':
                        try:
				self.TCPscanner()
	                except KeyboardInterrupt:
        	                print "[*] Finalizado pelo usuário."
                	        os.system('kill %d' % os.getpid())
                       		sys.exit(1)
                
		elif self.mode == 'arp': 
			try:
				self.socket = conf.L2socket(iface=self.interface)
				self.ARPscanner()
			except KeyboardInterrupt:
				print "[*] Finalizado pelo usuário."
				os.system('kill %d' % os.getpid())
				sys.exit(1)
		else:
			print "[!] Modo de scan inválido ./pythem.py --help para verificar sua sintaxe."
