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
import sys
import os

class PcapReader(object):


	def __init__(self, file):
		self.file = file
		self.packets = rdpcap(file)
	def printHelp(self):
		print """\n


		[ PytheM - Leitor Forense de arquivos pcap ]

	ARQUIVO - [ {} ]

help:   		Mostra esta mensagem de ajuda.
clear:			Limpa a tela.
exit/quit:		Finaliza o programa

show:			Mostra todos os pacotes e seus respectivos números.
conversations:		Mostra pictograma com as conversas entre hosts do arquivo analisado.
filter:			Abre dialogo para filtragem no arquivo .pcap, utilizar filtro no formato tcpdump.

packetdisplay [num]:	Mostra o pacote selecionado pelo número por completo.
packetload [num]:	Mostra o conteúdo do pacote selecionado por seu número.
""".format(self.file)	

	def All(self,p):
		print p
		print

	def filter_lookup(self,p):
		if IP in p:
			ip_src = p[IP].src
			ip_dst = p[IP].dst
			if p.haslayer(Raw):
				print str(ip_src) + "-->" + str(ip_dst) + "\n" + p.getlayer(Raw).load 		

	def start(self):
		while True:
			try:
				self.command = raw_input("pforensic> ")
				self.argv = self.command.split()
				self.input_list = [str(a) for a in self.argv]

                                if self.input_list[0]  == 'packetdisplay':
                                        try:self.packets[int(self.input_list[1])].show()
					except Exception as e: print "[!] Exceção encontrada: {}".format(e)
		
				elif self.input_list[0] == 'filter':
					try:
						self.filt = raw_input("[+] Informe o filtro: ")
						sniff(offline="{}".format(self.file),filter = "{}".format(self.filt),prn=self.All)
					except Exception as e: print "[!] Exceção encontrada: {}".format(e)

				elif self.input_list[0] == 'packetload':
					try:
						print "[+] Payload do pacote {}: ".format(self.input_list[1])
						self.filter_lookup(self.packets[int(self.input_list[1])])
					
					except Exception as e: print "[!] Exceção encontrada: {}".format(e)


				elif self.input_list[0]  == 'exit':
					sys.exit(0)
				elif self.input_list[0] == 'quit':
					sys.exit(0)
				elif self.input_list[0] == 'help':
					self.printHelp()
				elif self.input_list[0] == 'clear':
					os.system('clear')
				elif self.input_list[0] == 'ls':
					os.system('ls')
				elif self.input_list[0] == 'summary':
					try:self.packets.summary()
					except Exception as e: print "[!] Exceção encontrada: {}".format(e)
				elif self.input_list[0] == 'show':
					try:self.packets.show()
					except Exception as e: print "[!] Exceção encontrada: {}".format(e)	
				elif self.input_list[0] == 'conversations':
					try:self.packets.conversations()
					except Exception as e: print "[!] Exceção encontrada: {}".format(e)
				else:
					print "[-] Informe uma opção válida."				

                        except KeyboardInterrupt:
                                print "[*] Finalizado pelo usuário."
                                sys.exit(0)





