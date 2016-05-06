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
from time import sleep
import os
import sys
import threading
import signal
import argparse

print get_banner()

pythem_version = '0.1.6'
pythem_codename = 'Coral Snake'

if os.geteuid() !=0:
	sys.exit("[-] Apenas para roots kido!")



if __name__ == '__main__':

# Opções

	parser = argparse.ArgumentParser(description="PytheM v{} = '{}'".format(pythem_version, pythem_codename),version="{} - '{}'".format(pythem_version,pythem_codename),usage="pythem.py -i interface [plugin] [plugin_options]", epilog="By: m4n3dw0lf")
	parser.add_argument("-i","--interface",required=True,type=str, help="Interface de rede para ouvir.")
	parser.add_argument("-g","--gateway",dest='gateway', help="Endereço IP do gateway. ex: './pythem.py -i wlan0 --spoof -g 10.0.0.1'.")
	parser.add_argument("-t","--targets",dest='targets', help="Endereço/Range IP do alvo. ex: './pythem.py -i wlan0 --spoof -g 10.0.0.1 -t 10.0.0.2'.")
	parser.add_argument("--scan", action='store_true', help="Faz scan em uma Range IP para descobrir hosts. ex: './pythem.py -i wlan0 --scan -t 192.168.0.0/24 --mode arp'.")
	parser.add_argument("--mode",type=str, dest='mode', default='tcp',choices = ["tcp","arp","manual"], help="Modo de scan: manual,tcp e arp padrão=[tcp].")
	parser.add_argument("--spoof", action='store_true', help="Redireciona tráfego usando ARPspoofing. ex: './pythem.py -i wlan0 --spoof -g gateway -t alvos'")
	parser.add_argument("--arpmode",type=str, dest='arpmode', default='rep', choices=["rep", "req"], help=' modo de ARPspoof: respostas(rep) ou requisições (req) [padrão: rep].')
	parser.add_argument("--sniff", action="store_true", help="Habilita o sniffing de pacotes.")
	parser.add_argument("--filter",type=str, dest='filter', default='dns', choices=['dns','http','manual'], help=" modo de sniffing: dns,http ou manual <porta> [padrão=dns]. ex: './pythem.py -i wlan0 --spoof -g 192.168.1.1 --filter http'")
	parser.add_argument("--ssh", action='store_true', help="Espera por uma conexão tcp reversa em SSH do alvo. ex: ./pythem.py --ssh -s -p 7001")
	parser.add_argument("-s","--server",dest='server',nargs='?' ,const='0.0.0.0', help="Endereço IP do servidor a escutar, padrão[0.0.0.0']")
	parser.add_argument("-p","--port",dest='port',nargs='?', const=7000, help="Porta do servidor a escutar, padrão=[7000]")
	parser.add_argument("--bruter", action='store_true', help="Inicializa um ataque de força bruta, necessita de wordlist.")
	parser.add_argument("--service", type=str, dest='service', choices=["ssh"],help="Serviço a ser atacado por força bruta. ex: ./pythem.py -i wlan0 --bruter --service ssh -t 10.0.0.1 -f /usr/share/wordlist.txt -u username")
	parser.add_argument("-f","--file",dest='file',help ="Caminho para a wordlist.")
	parser.add_argument("-u","--username",dest='username',help ="Usuário a ser utilizado no ataque de força bruta.")
	parser.add_argument("--geoip",action='store_true',help="Determina aproximadamente a geolocalização do endereço IP. ex:./pythem.py -i wlan0 --geoip --target 216.58.222.46")
	parser.add_argument("--decode", type=str,dest='decode', help="Decodifica um texto com o padrão determinado. ex: ./pythem.py -i wlan0 --decode base64")  
	parser.add_argument("--encode", type=str, dest='encode', help="Codifica um texto com o padrão determinado. ex: ./pythem.py -i wlan0 --encode hexa")

	if len(sys.argv) < 2:
    		parser.print_help()
    		sys.exit(1)

	args = parser.parse_args()


	interface = args.interface
	gateway = args.gateway
	targets = args.targets
	myip = get_myip(interface)
	mymac = get_mymac(interface)
	based = str(args.decode)
	basee = str(args.encode)
	mode = args.mode
	arpmode = args.arpmode
	filter = args.filter
	
	server = args.server
	port = args.port

	service = args.service
	file = args.file
	username = args.username
			
	

	if args.decode:
		try:print decode(based)
		except KeyboardInterrupt:
			print "\n[*] Finalizado pelo usuário."
			sys.exit(0)
	if args.encode:
		try:print encode(basee)
		except KeyboardInterrupt:
			print "\n[*] Finalizado pelo usuário."
			sys.exit(0)


	if args.scan:
		try:
			from modules.scanner import Scanner
			scan = Scanner(targets,interface,mode)
			scan.start()
		
		except KeyboardInterrupt:
			print "[*] Finalizado pelo usuário."
			sys.exit(1)
				

	elif args.spoof and args.sniff:
		try:
			from modules.arpoisoner import ARPspoof
			spoof = ARPspoof(gateway,targets, interface, arpmode, myip, mymac)
			spoof.start()
			from modules.sniffer import Sniffer
			sniff = Sniffer(interface, filter)
			sniff.start()

		except KeyboardInterrupt:
			spoof.stop()
			print "[*] Finalizado pelo usuário."
			sys.exit(1)
	
	elif args.spoof:
		try:
			print "[*] Utilize --sniff para sniffar pacotes interceptados, poisoning em threading."
			from modules.arpoisoner import ARPspoof
			spoof = ARPspoof(gateway,targets,interface,arpmode, myip, mymac)
			spoof.start()
			
		except KeyboardInterrupt:
			spoof.stop()
			print "[*] Finalizado pelo usuário."
			sys.exit(1)
	
	elif args.sniff:
		try:
			from modules.sniffer import Sniffer
			sniff = Sniffer(interface,filter)
			sniff.start()
		
		except KeyboardInterrupt:
			print "[*] Finalizado pelo usuário."
			sys.exit(1)
		

	elif args.ssh:
		try:
			from modules.reverse_shell import Server
			server = Server(server,port)
			server.start()
		except KeyboardInterrupt:
			server.stop()
			print "[*] Finalizado pelo usuário."
			sys.exit(1)

	elif args.bruter:
		try:
			from modules.ssh_brutter import SSHbrutus
			brutus = SSHbrutus(targets, username, file)
			brutus.start()
		except KeyboardInterrupt:
			print "[*] Finalizado pelo usuário."
			sys.exit(1)


	elif args.geoip:
		try:
			from modules.geoip import Geoip
			path = "config/GeoLiteCity.dat"
			iptracker = Geoip(targets,path)
		
		except KeyboardInterrupt:
			print "[*] Finalizado pelo usuário."
			sys.exit(1)	

	else:
		print "Selecione uma opção válida."
		sys.exit(1)

	
