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
from modules.banners import*
from modules.utils import*
from modules.arpoisoner import *
from modules.arpscanner import *
import os
import sys
import threading
import signal
import argparse

print get_banner()

pythem_version = '0.1.1'
pythem_codename = 'Anaconda'

if os.geteuid() !=0:
	sys.exit("[-] Apenas para roots kido!")

	

if __name__ == '__main__':

# Opções

	parser = argparse.ArgumentParser(description="PytheM v{} = '{}'".format(pythem_version, pythem_codename),version="{} - '{}'".format(pythem_version,pythem_codename),usage="pythem.py -i interface [plugin] [plugin_options]", epilog="By: m4n3dw0lf")

	parser.add_argument("-i","--interface",required=True, type=str, help="Interface de rede para ouvir.")
	parser.add_argument("-g","--gateway",dest='gateway', help="Endereço IP do gateway. ex: 'pythem.py -i wlan0 --spoof -g 10.0.0.1'.")
	parser.add_argument("-t","--targets",dest='targets', help="Endereço/Range IP do alvo. ex: 'pythem.py -i wlan0 --spoof -g 10.0.0.1 -t 10.0.0.2'.")
	parser.add_argument("--scan", type=str, help="Faz scan em uma Range IP para descobrir hosts. ex: 'pythem.py -i wlan0 -s 192.168.0.0/24'.")
	parser.add_argument("--spoof", action='store_true', help="Redireciona tráfego usando ARPspoofing. ex: 'pythem.py -i wlan0 --spoof [spoof options]'")
	parser.add_argument("--arpmode",type=str, dest='arpmode', default='rep', choices=["rep", "req"], help=' modo de ARPspoof: respostas(rep) ou requisições (req) [default: rep]')


	if len(sys.argv) == 1:
    		parser.print_help()
    		sys.exit(1)

	
	args = parser.parse_args()


	interface = args.interface
	range = args.scan
	gateway = args.gateway
	targets = args.targets
	myip = get_myip(interface)
	mymac = get_mymac(interface)
	arpmode = args.arpmode

	scan = ARPscanner(range,interface)
	spoof = ARPspoof(gateway,targets, interface, arpmode, myip, mymac)	


	if args.scan:
		try:
			scan.scan()

		except KeyboardInterrupt:
			print "[*] Finalizado pelo usuário."
			sys.exit(1)


	elif args.spoof:
		try:
			spoof.start()
			
		except KeyboardInterrupt:
			print "[*] Finalizado pelo usuário."
			spoof.stop()
			sys.exit(1)
