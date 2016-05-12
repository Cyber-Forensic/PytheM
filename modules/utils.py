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

import os
import sys
import socket
import fcntl
import struct



def decode(base):
        text = raw_input("[*] Texto a ser decodificado: ")
        decode = text.decode('{}'.format(base))
	result = "[+] Resultado: {}".format(decode)
	return result

def encode(base):
        text = raw_input("[*] Texto a ser codificado: ")
	encode = text.encode('{}'.format(base))
	result = "[+] Resultado: {}".format(encode)
	return result

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
		print "[*] Liberando o forwarding de pacotes"
def iptables():
	os.system('iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -F && iptables -X && iptables -t nat -F && iptables -t nat -X')
	print "[*] Redefinindo iptables"


def module_check(module):
	confirm = raw_input("[-] Você checou se seu sistema tem [%s] instalado?, gostaria de tentar instalá-lo? (apt-get install %s será executado caso sim [s/n]: " % (modules,module))
	if confirm == 's':
		os.system('apt-get install %s' % module)
	else:
		print "[-] Finalizado"
		sys.exit(1)

def startmon(mon_iface):
	iface = str(mon_iface)
	try:
		os.system("airmon-ng check kill")
		os.system("airmon-ng start %s" % iface)
	except:
		module_check('aircrack-ng')
def stopmon(mon_iface):
	iface = str(mon_iface)
	try:
		os.system("airmon-ng stop %s" % iface)
		os.system("service network-manager restart")
	except Exception as e:
		print "[*] Exceção encontrada: {}".format(e)
