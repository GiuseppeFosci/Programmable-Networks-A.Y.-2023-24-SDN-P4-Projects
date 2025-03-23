import os
import time
from scapy.all import sr1, IP, ICMP, conf

TARGET_IP = "20.0.1.15"
HOST_IP_CIDR = "20.0.1.10/24"  # IP con CIDR
INTERFACES = ["eth0", "eth1", "eth2", "eth3"]

def set_active_interface(active_intf):
    """
    Attiva solo l'interfaccia specificata e disattiva le altre.
    Esegue il flush degli indirizzi, assegna HOST_IP_CIDR, aggiorna la default route
    e forza Scapy ad usare questa interfaccia.
    Inoltre, forza la risoluzione ARP per il gateway.
    """
    for intf in INTERFACES:
        if intf == active_intf:
            os.system(f"ifconfig {intf} up")
            # Flush e assegnazione IP
            os.system(f"ip addr flush dev {intf} && ip addr add {HOST_IP_CIDR} dev {intf}")
            # Aggiorna la default route per usare questa interfaccia
            # Nota: se il gateway ha un IP specifico, potresti doverlo indicare (es. 'via <gateway_ip>')
            os.system(f"ip route replace default dev {intf}")
            # Imposta l'interfaccia di default per Scapy e resincronizza la tabella di routing
            conf.iface = active_intf
            conf.route.resync()
            print("Interfaccia attiva:", intf)
            
            # Forza la risoluzione ARP: utilizza 'arping' per popolare la cache ARP
            # Se 'arping' è installato, usa questo comando
            os.system(f"arping -c 1 -I {intf} {TARGET_IP}")
            # Attendi qualche secondo per permettere la risoluzione ARP
            time.sleep(5)
        else:
            os.system(f"ifconfig {intf} down")

def send_icmp_ping(target_ip):
    """
    Invia un ping ICMP utilizzando l'interfaccia configurata in conf.iface.
    """
    pkt = IP(dst=target_ip)/ICMP()
    reply = sr1(pkt, iface=conf.iface, timeout=2, verbose=0)
    if reply:
        print(f"Ping a {target_ip} riuscito tramite {conf.iface}.")
    else:
        print(f"Ping a {target_ip} fallito tramite {conf.iface}.")

def main():
    while True:
        for intf in INTERFACES:
            set_active_interface(intf)
            print(f"Simulo collegamento tramite {intf}")
            # Esegue 3 ping al gateway
            for _ in range(3):
                send_icmp_ping(TARGET_IP)
                time.sleep(1)
            # Attende 10 secondi prima di passare all'interfaccia successiva
            time.sleep(10)

if __name__ == "__main__":
    main()
