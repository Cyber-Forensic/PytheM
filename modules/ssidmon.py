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

class SSIDmon(object):

	def __init__(self,interface):

		self.ap_list = []
		self.interface = interface

	def PacketHandler(self,p):
		if p.haslayer(Dot11):
			if p.type == 0 and p.subtype == 8:
				if p.addr2 not in self.ap_list:
					self.ap_list.append(p.addr2)		
					print "[+] AP MAC: {} com SSID: {} ".format(p.addr2,p.info)
	
	def start(self):

		try:
			sniff(iface=self.interface, prn = self.PacketHandler)
		
		except Exception as e:
			print "[*] Exceção encontrada: {}".format(e)
