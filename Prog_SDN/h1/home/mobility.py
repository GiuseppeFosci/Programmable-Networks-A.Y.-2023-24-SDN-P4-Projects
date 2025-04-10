import os
import time
from scapy.all import sr1, send, IP, ICMP, conf, arping

TARGET_IP = "20.0.1.15"
HOST_IP_CIDR = "20.0.1.10/24"  # IP con CIDR
INTERFACES = ["eth0", "eth1", "eth2", "eth3"]

def set_active_interface(active_intf):
    """
    Attivo solo l'interfaccia specificata e disattiva le altre.
    Esegue il flush degli indirizzi, assegna HOST_IP_CIDR, aggiorna la default route
    e forza Scapy ad usare questa interfaccia.
    """
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
    """
    Invio un pacchetto ICMP Echo Request senza attendere una risposta.
    """
    pkt = IP(dst=target_ip)/ICMP()
    send(pkt, iface=conf.iface, verbose=False)
    print(f"Inviato ICMP Echo Request a {target_ip} tramite {conf.iface} (senza attesa risposta)")

def main():
    while True:
        for intf in INTERFACES:
            set_active_interface(intf)
            print(f"Simulo collegamento tramite {intf}")  
            send_icmp_ping_no_reply(TARGET_IP)
            time.sleep(10)

if __name__ == "__main__":
    main()
