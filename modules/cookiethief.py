#!/usr/bin/env python2.7
#coding=UTF-8

import mechanize


class CookieThief(object):

	def __init__(self,target):
		self.target = target

	def Normal(self):
		br = mechanize.Browser()
		br.open(self.target)
		cookie = br._ua_handlers['_cookies'].cookiejar
		print cookie


	def Auth(self):
		login = raw_input("[+] Enter the input name of the username box: ")
		psswd = raw_input("[+] Enter the input name of the password box: ")
		user = raw_input("[+] Enter the username to log-in: ")
		password = raw_input("[+] Enter the password to log-in: ")
		br = mechanize.Browser()
		br._ua_handlers['_cookies'].cookiejar
		br.set_handle_robots(False)
		br.open(self.target)
		br.select_form(nr=0)
		br['{}'.format(login)] = user
		br['{}'.format(psswd)] = password
		br.submit()
		response = br.response()
		cookie = br._ua_handlers['_cookies'].cookiejar
		print cookie

		#c = str(cookie)
		#redundance, cookie1 = c.split("=")
		#cookie2, signature = cookie1.split("--")
		#res = base64.b64decode(urllib.unquote(cookie2))
		#print res


	def start(self):
		choice = raw_input("[*] Make cookie dump through Authenticated or Normal webpage request? [a/n]: ")
		if choice == 'a' or choice == 'A':
			try:self.Auth()
			except Exception as e:
				print "[*] Exception caught: {}".format(e)
		elif choice == 'n' or choice == 'N':
			try:self.Normal()
			except Exception as e:
				print "[*] Exception caught: {}".format(e)
		else:
			print "[!] Select a valid option [a] to Authenticate through webpage or [n] to Normal webpage request."
			self.start()
