from scapy.layers.l2 import Ether
from .utils import anonymize_mac


def anonymize_ether(ether: Ether) -> Ether:
    """
    Anonymize a packet's Ether layer.
    
    Args:
        ether (scapy.Ether): Ether layer to anonymize
    Returns:
        scapy.Ether: anonymized Ether layer
    """
    ether.setfieldval("src", anonymize_mac(ether.getfieldval("src")))
    ether.setfieldval("dst", anonymize_mac(ether.getfieldval("dst")))
    return ether
