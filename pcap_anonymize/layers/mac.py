"""
Anonymize MAC addresses.
"""

from hashlib import sha256
from scapy.layers.l2 import Ether, ARP
from scapy.layers.dhcp import BOOTP, DHCP

BASE_HEX = 16
BYTE_ORDER = "big"

# DHCP-related constants
DHCP_MAGIC_COOKIE = 0x63825363
DHCP_OPTION_CLIENT_ID = "client_id"
DHCP_CLIENT_ID_TYPE_ETH = 1

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

    ## Locally administered address
    if is_local:
        bit_mask = ig_bit | ul_bit

        # Compute SHA-256 hash of the MAC address
        mac_sha256 = sha256()
        for byte in mac_split:
            mac_sha256.update(int(byte, BASE_HEX).to_bytes(1, BYTE_ORDER))
        digest = mac_sha256.digest()

        first_byte = (digest[0] & 0b11111100) | bit_mask  # Keep I/G and U/L bits
        return f"{first_byte:02x}:" + ':'.join(f"{digest[i]:02x}" for i in range(1, 6))
    

    ## Universally administered address
    
    # Compute SHA-256 hash based on the three least-significant bytes
    mac_sha256 = sha256()
    for byte in mac_split[3:]:
        mac_sha256.update(int(byte, BASE_HEX).to_bytes(1, BYTE_ORDER))
    digest = mac_sha256.digest()

    # Keep OUI and anonymize the rest
    return (
        ':'.join(mac_split[:3]) +                          # Keep OUI
        ':' +
        ':'.join(f"{digest[i]:02x}" for i in range(0, 3))  # Hashed last 3 bytes
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


def anonymize_dhcp(dhcp: BOOTP) -> BOOTP:
    """
    Anonymize a packet's DHCP layer MAC addresses.
    
    Args:
        dhcp (scapy.BOOTP): DHCP layer to anonymize
    Returns:
        scapy.BOOTP: anonymized DHCP layer
    """
    # Anonymize client hardware address
    chaddr = dhcp.getfieldval("chaddr")[0:6]
    dhcp.setfieldval("chaddr", anonymize_mac(chaddr))

    # Check if BOOTP layer contains DHCP options
    options = dhcp.getfieldval("options")
    cookie = int.from_bytes(options[:4], BYTE_ORDER)
    if cookie != DHCP_MAGIC_COOKIE:
        return dhcp

    # BOOTP layer contains DHCP options
    # Anonymize Client Identifier option
    dhcp = dhcp.getlayer(DHCP)
    
    if dhcp is None or dhcp.options is None:
        return dhcp
    
    for i, (code, value) in enumerate(dhcp.options):
        if code == DHCP_OPTION_CLIENT_ID and value[0] == DHCP_CLIENT_ID_TYPE_ETH:
            mac = ":".join(f"{byte:02x}" for byte in value[1:7])
            dhcp.options[i] = (code, anonymize_mac(mac))
            break

    return dhcp
