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
		self.portRange = [21,22,23,25,53,57,80,107,109,110,115,118,123,135,137,138,139,161,389,443,445,465,995,1025,1026,1027,1035,1234,1243,3000,3128,3306,3389,3872,4444,6346,6667,6667,8080,12345,12346,16660,18753,20034,20432,20433,27374,27444,27665,31335,31337,33270,33567,33568,40421,60008,65000]		
		self.mode = mode
		self.portManual = []
	
	def get_range(self, targets):
                if targets is None:
                        return None
		if targets is not None:
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

			except Exception as e:
     				sys.exit("[!] Exception caught: {}").format(e)




	def portScan(self, hosts, ports):
		for dstPort in self.ports:
			srcPort = random.randint(1025,65534)
			resp = sr1(IP(dst=self.targetip)/TCP(sport=srcPort,dport=dstPort,flags="S"),timeout=1,verbose=0)
			if (str(type(resp)) == "<type 'NoneType'>"):
				print "[-]{}:{} is filtered.".format(self.targetip,str(dstPort))
			elif(resp.haslayer(TCP)):
				if (resp.haslayer(TCP)):
					if(resp.getlayer(TCP).flags == 0x12):
						send_rst = sr(IP(dst=self.targetip)/TCP(sport=srcPort, dport=dstPort, flags="R"), timeout=1,verbose=0)
						print "[+]{}:{} is open.".format(self.targetip,str(dstPort))
			elif(resp.haslayer(ICMP)):
				if(int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
					print "[-]{}:{} is filtered.".format(self.targetip,str(dstPort))

	def MANUALscanner(self):
		
		liveCounter = 0
		self.portManual.append(input("[+] Enter the port: "))
		self.ports = self.portManual
		print "\n[+] Manual TCP Scan initialized..."
		for target in self.range:
			self.targetip = str(target)
			resp = sr1(IP(dst=str(self.targetip))/ICMP(),timeout=2,verbose=0)
                        if (str(type(resp)) == "<type 'NoneType'>"):
                                print "\n[*]" + str(self.targetip) + " is down or not responding.\n"
                        elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                                print "\n[*]" + str(self.targetip) + " is blocking ICMP.\n"
                        else:
                                print "\n[*]" + str(self.targetip) + " is online: "
                                self.portScan(str(self.targetip),self.portManual)
                                liveCounter += 1
          	print "Of "+ str(len(self.range)) + " scanned hosts, " + str(liveCounter) + " are online."

		

        def TCPscanner(self):

		liveCounter = 0
                self.ports = self.portRange
		print "\n[+] TCP Scan initialized..."
		for target in self.range:
	
			self.targetip = str(target)
                        resp = sr1(IP(dst=str(self.targetip))/ICMP(),timeout=2,verbose=0)
                        if (str(type(resp)) == "<type 'NoneType'>"):
                                 print "\n[*]" + str(self.targetip) + " is down or not responding.\n"
                        elif (int(resp.getlayer(ICMP).type)==3 and int(resp.getlayer(ICMP).code) in [1,2,3,9,10,13]):
                                 print "\n[*]" + str(self.targetip) + " is blocking ICMP.\n"
			else:
                                 print "\n[*]" + str(self.targetip) + " is online: "
	      			 self.portScan(str(self.targetip),self.portRange)
                                 liveCounter += 1
		print "Of "+ str(len(self.range)) + " scanned hosts, " + str(liveCounter) + " are online."


	

	def ARPscanner(self):
                try:
	                print "\n[+] ARP Scan initialized...\n"
         	        conf.verb = 0
                        ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=self.arprange), timeout = 2, iface=self.interface, inter=0.1)
                        for snd,rcv in ans:
                                print rcv.sprintf(r"[+] IP: %ARP.psrc% has the MAC: %Ether.src%")

                except KeyboardInterrupt:
                        print "\n[*] User requested shutdown."
                        sys.exit(1)



	def start(self):
		
		if self.mode == 'manual':
			try:
				self.MANUALscanner()
	                except KeyboardInterrupt:
        	                print "[*] User requested shutdown."
                	        os.system('kill %d' % os.getpid())
                	        sys.exit(1)
			
		elif self.mode == 'tcp':
                        try:
				self.TCPscanner()
	                except KeyboardInterrupt:
        	                print "[*] User requested shutdown."
                	        os.system('kill %d' % os.getpid())
                       		sys.exit(1)
                
		elif self.mode == 'arp': 
			try:
				self.socket = conf.L2socket(iface=self.interface)
				self.ARPscanner()
			except KeyboardInterrupt:
				print "[*] User requested shutdown."
				os.system('kill %d' % os.getpid())
				sys.exit(1)


		else:
			print "[!] Invalid scan mode ./pythem.py --help to check your sintax."
