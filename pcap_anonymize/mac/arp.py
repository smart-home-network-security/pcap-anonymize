from scapy.layers.l2 import ARP
from .utils import anonymize_mac


def anonymize_arp(arp: ARP) -> ARP:
    """
    Anonymize a packet's ARP layer.
    
    Args:
        packet (scapy.ARP): ARP layer to anonymize
    Returns:
        scapy.ARP: anonymized ARP layer
    """
    arp.setfieldval("hwsrc", anonymize_mac(arp.getfieldval("hwsrc")))
    arp.setfieldval("hwdst", anonymize_mac(arp.getfieldval("hwdst")))
    return arp