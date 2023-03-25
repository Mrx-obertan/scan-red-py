import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # para ocultar la advertencia de Scapy

from scapy.all import *
import time

def scan_network():
    # obtener la dirección IP de la red local
    local_ip = str(get_if_addr(conf.iface))

    # definir el rango de direcciones IP a escanear
    ip_range = local_ip + '/24'

    # crear una lista vacía para guardar las direcciones IP que están disponibles
    available_ips = []

    # enviar paquetes ARP a todas las direcciones IP en el rango especificado
    arp_request = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(pdst=ip_range)
    answered, unanswered = srp(arp_request, timeout=2, verbose=0)

    # iterar sobre las respuestas para determinar qué direcciones IP están disponibles
    for packet in answered:
        mac = packet[1].hwsrc
        ip = packet[1].psrc
        if mac != '00:00:00:00:00:00' and ip != local_ip:
            available_ips.append(ip)

    return available_ips


def check_connection(ip):
    # enviar un paquete ICMP de prueba al host especificado
    ping = IP(dst=ip)/ICMP()
    response = sr1(ping, timeout=2, verbose=0)

    # determinar si se recibió una respuesta o no
    if response:
        return True
    else:
        return False


if __name__ == '__main__':
    # escanear la red y verificar la conexión de cada dirección IP disponible
    available_ips = scan_network()
    for ip in available_ips:
        if check_connection(ip):
            print(f'{ip} está disponible')
        else:
            print(f'{ip} no está disponible')
