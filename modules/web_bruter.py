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

import urllib2
import threading
import Queue
import urllib
import sys
import os
import mechanize

class WEBbrutus(object):
	
	def __init__ (self, target,file):
		self.threads = 5
		self.target_url = target
		self.wordlist = file
		self.resume = None
		self.user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:19.0) Gecko/20100101 Firefor/19.0"
		self.word_queue = self.build_wordlist(self.wordlist)
		self.extensions = [".txt",".php",".bak",".orig",".inc",".doc"]
		self.line = "\n------------------------------------------------------------------------\n"


	def build_wordlist(self, wordlist):
		 # Le a lista de palavras
		wordlist = self.wordlist
		fd = open(self.wordlist,"rb")
		raw_words = fd.readlines()
		fd.close()
		found_resume = False
		words = Queue.Queue()

		for word in raw_words:
			word = word.rstrip()
			if self.resume is not None:
				if found_resume:
					words.put(word)
				else:
					if word == resume:
						found_resume = True
						print "Resuming wordlist from: %s" % resume
			else:
				words.put(word)
		return words

	
	def form_attempt(self,password):
                        br = mechanize.Browser()
                        br.set_handle_robots(False)
			br.open(self.target_url)
                        br.select_form(nr=0)
                        br['{}'.format(self.login)] = self.user           
                        br['{}'.format(self.psswd)] = password
			br.submit()
			response = br.response()
			print "[+] [User:{} Pass:{}] = {}".format(self.user,password,response.geturl())
			print

	def form_bruter(self):
		print
		try:
			self.login = raw_input("[+] Enter the id name of the username box: ")
			self.psswd = raw_input("[+] Enter the id name of the password box: ")
			self.user = raw_input("[+] Enter the username to brute-force the formulary: ")
			input_file = open(self.wordlist)
			for i in input_file.readlines():
				password = i.strip("\n")
				self.form_attempt(password)		
		except Exception as e:
			print "[!] Exception caught, check the fields according to the HTML page, Error: {}".format(e)
			

	def dir_bruter(self, word_queue,extensions=None):
		while not self.word_queue.empty():
			attempt = self.word_queue.get()
			attempt_list = []
			attempt_list.append("%s" % attempt)
			if "." not in attempt:
				attempt_list.append("%s/" % attempt)
			else:
				attempt_list.append("%s" % attempt)
			if extensions:
				for extension in extensions:
					attempt_list.append("%s%s" % (attempt,extension))



			for brute in attempt_list:
				url = "%s%s" % (self.target_url,urllib.quote(brute))
				try:
					headers = {}
					headers["User-Agent"] = self.user_agent
					r = urllib2.Request(url,headers=headers)
					response = urllib2.urlopen(r)
					if len(response.read()):
						print "[%d] ==> %s" % (response.code,url)
				except urllib2.URLError,e:
					if e.code != 404:
						print "!!! %d => %s" % (e.code,url)
					pass

	
	def start(self,mode):
                if mode == 'url':
                        print "[+] Content URLbuster initialized."
                        try:
                                for i in range(self.threads):
                                        t = threading.Thread(target=self.dir_bruter,args=(self.word_queue,self.extensions,))
                                        t.start()
                        except KeyboardInterrupt:
                                print "[*] User requested shutdown."
                                os.system('kill %d' % os.getpid())
                                sys.exit(0)
		
		elif mode == 'form':
			print "[+] Brute-Form Authentication initialized."
			try:
				self.form_bruter()
			except KeyboardInterrupt:
				print "[*] User requested shutdown."
				os.system('kill %d' % os.getpid())
				sys.exit(0)
