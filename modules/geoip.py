#!/usr/bin/env python2.7
#coding=UTF-8

from pygeoip import pygeoip 


class Geoip(object):

	

	def __init__(self, target):
		self.target = target
		self.gip = pygeoip.GeoIP("../config/GeoLiteCity.dat")
		self.search()
		
	def search(self):
		addr = self.target
		rec = self.gip.record_by_addr(addr)
		for key,val in rec.items():
			print "[~] %s: %s" %(key,val)
