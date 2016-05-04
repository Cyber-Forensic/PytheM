#!/usr/bin/env python2.7
#coding=UTF-8

from pygeoip import pygeoip 
import os
import sys

class Geoip(object):

	

	def __init__(self, target,path):
		self.target = target
		try:
			self.gip = pygeoip.GeoIP(path)
			self.search()
		
		except:
			print "[!] Você precisa estar dentro da pasta principal para executar o modulo geoip."
		
	def search(self):
		addr = self.target
		rec = self.gip.record_by_addr(addr)
		for key,val in rec.items():
			print "[~] %s: %s" %(key,val)
