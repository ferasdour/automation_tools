"""
So long story short, trying to see what else will do this. 

 1:  SBE1V1K.lan                                           3.142ms 
 2:  vlan-200.ana05wxhctxbn.netops.charter.com             7.075ms 
 3:  lag-56.wxhctxbn01h.netops.charter.com                 8.494ms 
 4:  lag-38.rcr01dllstx97.netops.charter.com              12.345ms 
 5:  lag-100.rcr01ftwptxzp.netops.charter.com             13.750ms asymm  4 
 6:  lag-6.bbr01rvsdca.netops.charter.com                 50.344ms 
 7:  lag-1-10.crr03rvsdca.netops.charter.com              49.355ms asymm  8 
 8:  lag-305.crr02rvsdca.netops.charter.com               49.280ms 
 9:  lag-305.crr02mtpkca.netops.charter.com               60.820ms 
10:  lag-10.crr02mtpkca.netops.charter.com                50.756ms asymm  9 
11:  lag-320.dtr04mtpkca.netops.charter.com               47.263ms asymm 10 
12:  int-4-3.acr02mtpkca.netops.charter.com               52.721ms asymm 11 
13:  172.27.52.188                                        59.896ms reached

That's a private ip range that accidently routed within the ISP's network but outside the private networks
"""

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import *
import ipaddress, netifaces, re
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor

routes=[]
gateways=netifaces.gateways()
for i in gateways['default']:
 routes.append(gateways[i][0][0])

def arpips():
 ips = []
 try:
  with os.popen('arp -a') as f:
   arp=f.read()
   for line in re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', arp):
    ips.append(line)
 except:
  pass
 return ips

def loop(addr):
 #print("test: %s" % str(addr))
 ans, unans = traceroute(str(addr),verbose=0)
 suspicious=[]
 try:
  for i in ans:
   ipaddr=i.answer.src
   if ipaddress.ip_address(ipaddr).is_private == True:
    if ipaddr not in routes:
     suspicious.append(ipaddr)
 except:
  pass
 return set(suspicious)

def rangeloop(r):
  print("Starting Range: %s" % r)
  for addr in ipaddress.IPv4Network(r):
   with ThreadPoolExecutor(max_workers=10) as traceexecutor:
    tracefutures=[]
    if str(addr) not in arp:
     tracefutures.append(traceexecutor.submit(loop, addr))
    for f in concurrent.futures.as_completed(tracefutures):
     if len(f.result()) != 0:
         print("Possible: %s" % f.result())

arp=arpips()
ranges=['192.168.0.0/16', '172.16.0.0/12', '224.0.0.0/4']
with ProcessPoolExecutor(max_workers=3) as rangeexecutor:
 rangefutures=[]
 for r in ranges:
  rangeexecutor.submit(rangeloop, r)
concurrent.futures.as_completed(rangefutures)