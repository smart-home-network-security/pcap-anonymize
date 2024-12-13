"""
Anonymize MAC addresses.
"""

import random
import secrets
from scapy.layers.l2 import Ether, ARP

BASE_HEX = 16

# Special, well-known MAC addresses
special_macs = [
    "00:00:00:00:00:00",  # Default
    "ff:ff:ff:ff:ff:ff"   # Broadcast
]


def get_ig_bit(mac: str) -> int:
    """
    Get the I/G bit of a given MAC address.

    Args:
        mac (str): MAC address to get the I/G bit from
    Returns:
        int: 8-bit integer with the I/G bit set to its corresponding value,
             and all other bits set to 0 
    """
    first_byte = int(mac.split(":")[0], BASE_HEX)
    ig_mask = 0b00000001
    return first_byte & ig_mask


def get_ul_bit(mac: str) -> int:
    """
    Get the U/L bit of a given MAC address.

    Args:
        mac (str): MAC address to get the U/L bit from
    Returns:
        int: 8-bit integer with the U/L bit set to its corresponding value,
             and all other bits set to 0 
    """
    first_byte = int(mac.split(":")[0], BASE_HEX)
    ul_mask = 0b00000010
    return first_byte & ul_mask


def anonymize_mac(mac: str) -> str:
    """
    Anonymize a given MAC address.

    Args:
        mac (str): MAC address to anonymize
    Returns:
        str: anonymized MAC address
    """
    # Special MAC address
    if mac in special_macs:
        return mac
    
    ## Classic MAC address
    mac_split = mac.split(":")

    ## I/G bit: first byte, least-significant bit
    # I/G bit = 0 ==> Unicast address
    # I/G bit = 1 ==> Multicast address
    ig_bit = get_ig_bit(mac)
    is_multicast = bool(ig_bit)  # True ==> Multicast, False ==> Unicast

    # Multicast address:
    # do not anonymize
    if is_multicast:
        return mac

    ## U/L bit: first byte, second least-significant bit
    # U/L bit = 0 ==> Universally administered address (UAA)
    # U/L bit = 1 ==> Locally administered address (LAA)
    ul_bit = get_ul_bit(mac)
    is_local = bool(ul_bit)  # True ==> LAA, False ==> UAA

    # Locally administered address
    if is_local:
        bit_mask = ig_bit | ul_bit
        first_byte = (random.getrandbits(6) << 2) | bit_mask  # Keep I/G and U/L bits
        return f"{first_byte:02x}:" + ':'.join(secrets.token_hex(1) for _ in range(5))
    
    # Universally administered address
    return (
        ':'.join(mac_split[:3]) +                         # Keep OUI
        ':' +
        ':'.join(secrets.token_hex(1) for _ in range(3))  # Random last 3 bytes
    )
    

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
