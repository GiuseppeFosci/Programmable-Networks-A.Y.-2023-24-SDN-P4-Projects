import os
import time
from scapy.all import sr1, send, IP, ICMP, conf, arping

TARGET_IP = "20.0.1.15"
HOST_IP_CIDR = "20.0.1.10/24"  
INTERFACES = ["eth0", "eth1", "eth2", "eth3"]

def set_active_interface(active_intf):
    for intf in INTERFACES:
        if intf == active_intf:
            os.system(f"ifconfig {intf} up")
            os.system(f"ip addr flush dev {intf} && ip addr add {HOST_IP_CIDR} dev {intf}")
            os.system(f"ip route replace default dev {intf}")
            conf.iface = active_intf
            conf.route.resync()
            print("Interfaccia attiva:", intf)          
            arping(TARGET_IP, iface=active_intf, verbose=False)       
            time.sleep(5)
        else:
            os.system(f"ifconfig {intf} down")


def send_icmp_ping_no_reply(target_ip):
    pkt = IP(dst=target_ip)/ICMP()
    send(pkt, iface=conf.iface, verbose=False)
    print(f"Inviato ICMP Echo Request a {target_ip} tramite {conf.iface}")

def main():
    while True:
        for intf in INTERFACES:
            set_active_interface(intf)
            print(f"Simulo collegamento tramite {intf}")  
            send_icmp_ping_no_reply(TARGET_IP)
            time.sleep(10)

if __name__ == "__main__":
    main()
