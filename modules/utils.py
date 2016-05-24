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

import os
import sys
import socket
import fcntl
import struct
import urllib
import base64



def decode(base):
        text = raw_input("[*] String to be decoded: ")
        decode = text.decode('{}'.format(base))
	result = "[+] Result: {}".format(decode)
	return result

def encode(base):
        text = raw_input("[*] String to be encoded: ")
	encode = text.encode('{}'.format(base))
	result = "[+] Result: {}".format(encode)
	return result

def cookiedecode():
	cookie = raw_input("[+] Enter the cookie value: ")
	res = base64.b64decode(urllib.unquote(cookie))
	print
	print res

def get_myip(interface):
	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
	return socket.inet_ntoa(fcntl.ioctl(
		s.fileno(),
		0x8915,
		struct.pack('256s', interface[:15])
	)[20:24])


def get_mymac(interface):
    	s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    	info = fcntl.ioctl(s.fileno(), 0x8927,  struct.pack('256s', interface[:15]))
    	return ''.join(['%02x:' % ord(char) for char in info[18:24]])[:-1]		


def set_ip_forwarding(value):
	with open('/proc/sys/net/ipv4/ip_forward', 'w') as file:
		file.write(str(value))
		file.close()
		print "[*] Enabling the packet forwarding."
def iptables():
	os.system('iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')
	print "[*] Iptables redefined"


def module_check(module):
	confirm = raw_input("[-] Do you checked if your system has [%s] installed?, do you like to try installing? (apt-get install %s will be executed if yes [y/n]: " % (modules,module))
	if confirm == 'y':
		os.system('apt-get install %s' % module)
	else:
		print "[-] Terminated"
		sys.exit(1)

