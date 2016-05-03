#!/usr/bin/env python2.7
#coding=UTF8

from scapy.all import *
from netaddr import IPNetwork, IPRange, IPAddress, AddrFormatError
import random
import sys

class Scanner(object):

	def __init__(self,target,interface,mode):
		self.interface = interface
		self.targets = target
		self.range = self.get_range(target)
		self.portRange = [21,22,23,80,443,3000,3128,3128,3389,8080]
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
					elif(resp.getlayer(TCP).flags == 0x14):
						print "[-]{}:{} está fechada.".format(self.targetip,str(dstPort)) 
			elif(resp.haslayer(ICMP)):
				if(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
					print "[-]{}:{} está filtrada.".format(self.targetip,str(dstPort))
			

	def MANUALscanner(self):
		
		liveCounter = 0
		try:
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

		
		except KeyboardInterrupt:
			print "[*] Finalizado pelo usuário."
			sys.exit(1)



        def TCPscanner(self):

		liveCounter = 0
                try:
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


                except KeyboardInterrupt:
                        print "Finalizado pelo usuário."
                        sys.exit(1)
	

	def ARPscanner(self):
		try:
			print "\n[+] ARP Scan inicializado...\n"
			conf.verb = 0
			for target in self.range:
				targetip = str(target)
				packet = Ether(dst="ff:ff:ff:ff:ff:ff:ff")/ARP(op="who-has",pdst=targetip)
				
				try:
					
					resp, _ = sndrcv(self.socket, packet, timeout=3, verbose=False)
					if len(resp) > 0:
						targetmac = resp[0][1].hwsrc
						print "[+] IP:{} tem o MAC:{}\n".format(targetip, targetmac)
					else:
						print "[-] Não foi possivel resolver o endereço MAC de {}\n".format(targetip)
				except Exception as e:
					resp = ''
					if "Interrupted system call" not in e:
						print "[!] Exceção ocorreu ao scanear {}: {}".format(targetip, e)
					
		

		except KeyboardInterrupt:
			print "[*] Finalizado pelo usuário."
			sys.exit(1)

	def start(self):
		
		if self.mode == 'manual':
			self.MANUALscanner()
		elif self.mode == 'tcp':
                        self.TCPscanner()
                elif self.mode == 'arp':
			self.socket = conf.L2socket(iface=self.interface)
			self.ARPscanner()
		else:
			print "[!] Modo de scan inválido ./pythem.py --help para verificar sua sintaxe."
