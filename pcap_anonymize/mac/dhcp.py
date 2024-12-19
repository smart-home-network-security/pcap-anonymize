from scapy.layers.dhcp import BOOTP, DHCP
from .utils import mac_bytes_to_str, mac_str_to_bytes, anonymize_mac


BYTE_ORDER = "big"
DHCP_MAGIC_COOKIE = 0x63825363
DHCP_OPTION_CLIENT_ID = "client_id"
DHCP_CLIENT_ID_TYPE_ETH = 1


def anonymize_dhcp(dhcp: BOOTP) -> BOOTP:
    """
    Anonymize a packet's DHCP layer MAC addresses.
    
    Args:
        dhcp (scapy.BOOTP): DHCP layer to anonymize
    Returns:
        scapy.BOOTP: anonymized DHCP layer
    """
    # Anonymize client hardware address
    chaddr = mac_bytes_to_str(dhcp.getfieldval("chaddr")[0:6])
    dhcp.setfieldval("chaddr", mac_str_to_bytes(anonymize_mac(chaddr)))

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
    
    for i, option in enumerate(dhcp.options):
        # Option is not of format (code, value), skip
        if len(option) != 2:
            continue

        code, value = option
        if code == DHCP_OPTION_CLIENT_ID and value[0] == DHCP_CLIENT_ID_TYPE_ETH:
            mac_anon = mac_str_to_bytes(anonymize_mac(value[1:7]))
            dhcp.options[i] = (code, value[0].to_bytes(1, BYTE_ORDER) + mac_anon)
            break

    return dhcp