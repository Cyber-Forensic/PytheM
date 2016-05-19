#!/usr/bin/env python2.7
#coding=UTF-8

# Copyright (c) 2016 m4n3dw0lf
#
# This file is part of the program PytheM
#
# PytheM is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License as
# published by the Free Software Foundation; either version 3 of the
# License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
# General Public License for more details.
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307
# USA

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
					print "[+] AP MAC: {} with SSID: {} ".format(p.addr2,p.info)
	
	def start(self):

		try:
			sniff(iface=self.interface, prn = self.PacketHandler)
		
		except Exception as e:
			print "[*] Exception caught: {}".format(e)
