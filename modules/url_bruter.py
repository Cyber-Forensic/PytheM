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

import urllib2
import threading
import Queue
import urllib


class URLbrutus(object):
	
	def __init__ (self, target,file):
		self.threads = 5
		self.target_url = target
		self.wordlist = file
		self.resume = None
		self.user_agent = "Mozilla/5.0 (X11; Linux x86_64; rv:19.0) Gecko/20100101 Firefor/19.0"
		self.word_queue = self.build_wordlist(self.wordlist)
		


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


	def dir_bruter(self,extensions=None):
		while not self.word_queue.empty():
			attempt = self.word_queue.get()
			attempt_list = []

			if "." not in attempt:
				attempt_list.append("%s" % attempt)
			else:
				attempt_list.append("/%s" % attempt)

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
					if hasattr(e, 'code') and e.code != 404:
						print "!!! %d => %s" % (e,code,url)
					pass

	
	def start(self):
		print "[+] Content URLbuster inicializado."
		for i in range(self.threads):
			t = threading.Thread(target=self.dir_bruter)
			t.start()
