# Scapy
from scapy.packet import Packet
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dhcp import BOOTP

# Custom
from .ether import anonymize_ether
from .arp import anonymize_arp
from .dhcp import anonymize_dhcp


def anonymize_pkt_macs(packet: Packet) -> None:
    """
    Anonymize a packet's MAC addresses.
    
    Args:
        packet: scapy packet to anonymize
    """
    # Ethernet
    try:
        anonymize_ether(packet.getlayer(Ether))
    except AttributeError:
        pass

    # ARP
    try:
        anonymize_arp(packet.getlayer(ARP))
    except:
        pass
    
    # DHCP
    try:
        anonymize_dhcp(packet.getlayer(BOOTP))
    except AttributeError:
        pass
