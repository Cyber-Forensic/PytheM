#!/usr/bin/env python2.7
#coding=UTF-8

import pygeoip 


class Geoip(object):

	

	def __init__(self, target,path):
		self.target = target
		self.gip = pygeoip.GeoIP(path)
		self.search()
		
	def search(self):
		addr = self.target
		rec = self.gip.record_by_addr(addr)
		for key,val in rec.items():
			print "[~] %s: %s" %(key,val)
