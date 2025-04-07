#!/usr/bin/env python
import sys
import socket
import re
from subprocess import Popen, PIPE

from scapy.all import sendp, get_if_list, get_if_hwaddr
from scapy.all import Ether, IP, TCP, Raw, Packet, ByteField

# Custom Consensus header compatible with P4
class Consensus(Packet):
    name = "Consensus"
    fields_desc = [
        ByteField("allowed_count", 0),
        ByteField("drop_count", 0),
        ByteField("abstained_count", 0)
    ]

def get_if():
    ifs=get_if_list()
    iface=None # "h1-eth0"
    for i in get_if_list():
        if "eth0" in i:
            iface=i
            break;
    if not iface:
        print("Cannot find eth0 interface")
        exit(1)
    return iface

def get_dst_mac(ip):
    try:
        pid = Popen(["arp", "-n", ip], stdout=PIPE)
        s = pid.stdout.readlines()[1].decode('utf-8').strip()
        mac = re.search(r"(([a-f\d]{1,2}\:){5}[a-f\d]{1,2})", s).groups()[0]
        return mac
    except:
        return None

def main():
    dest_ip = "10.0.1.102"
    message = "Test message"

    addr = socket.gethostbyname(dest_ip)
    iface = get_if()

    tos = 0

    ether_dst = get_dst_mac(addr)

    if not ether_dst:
        print("Mac address for %s was not found in the ARP table" % addr)
        exit(1)

    print("Sending on interface %s to %s" % (iface, str(addr)))
    pkt = (Ether(src=get_if_hwaddr(iface), dst=ether_dst) /
           IP(dst=addr, tos=tos) /
           TCP(sport=12345, dport=80) /
           Consensus() /
           Raw(load=message))
    sendp(pkt, iface=iface, verbose=False)

if __name__ == '__main__':
    main()
