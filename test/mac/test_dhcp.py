from scapy.layers.dhcp import BOOTP, DHCP
from pcap_anonymize.mac import anonymize_dhcp, anonymize_pkt_macs
from pcap_anonymize.mac.utils import mac_str_to_bytes, get_ig_bit, get_ul_bit


### TEST CONSTANTS ###

mac_multicast = "01:00:00:00:00:00"
mac_multicast_bytes = b"\x01\x00\x00\x00\x00\x00"
mac_laa = "02:00:00:00:00:00"
mac_laa_bytes = b"\x02\x00\x00\x00\x00\x00"
mac_uaa = "00:11:22:33:44:55"
mac_uaa_bytes = b"\x00\x11\x22\x33\x44\x55"


### TEST FUNCTIONS ###

def test_anonymize_dhcp_multicast() -> None:
    """
    Test the function `anonymize_dhcp`,
    with multicast addresses.
    """
    # Client hardware address
    dhcp = BOOTP(chaddr=mac_str_to_bytes(mac_multicast))
    anonymize_dhcp(dhcp)
    assert dhcp.chaddr == mac_multicast_bytes
    anonymize_pkt_macs(dhcp)
    assert dhcp.chaddr == mac_multicast_bytes

    # Option: Client Identifier
    dhcp /= DHCP(options=[("client_id", b"\x01" + mac_str_to_bytes(mac_multicast))])
    anonymize_dhcp(dhcp)
    assert dhcp.getlayer(DHCP).options[0][1][1:7] == mac_multicast_bytes
    anonymize_pkt_macs(dhcp)
    assert dhcp.getlayer(DHCP).options[0][1][1:7] == mac_multicast_bytes


def test_anonymize_dhcp_laa() -> None:
    """
    Test the function `anonymize_dhcp`,
    with locally administered addresses.
    """
    # Client hardware address
    dhcp = BOOTP(chaddr=mac_str_to_bytes(mac_laa))
    anonymize_dhcp(dhcp)
    assert dhcp.chaddr != mac_laa_bytes
    assert get_ig_bit(dhcp.chaddr) == get_ig_bit(mac_laa_bytes)
    assert get_ul_bit(dhcp.chaddr) == get_ul_bit(mac_laa_bytes)

    anonymize_pkt_macs(dhcp)
    assert dhcp.chaddr != mac_laa_bytes
    assert get_ig_bit(dhcp.chaddr) == get_ig_bit(mac_laa_bytes)
    assert get_ul_bit(dhcp.chaddr) == get_ul_bit(mac_laa_bytes)


    # Option: Client Identifier
    dhcp /= DHCP(options=[("client_id", b"\x01" + mac_str_to_bytes(mac_laa))])
    anonymize_dhcp(dhcp)
    mac_anon = dhcp.getlayer(DHCP).options[0][1][1:7]
    assert mac_anon != mac_laa_bytes
    assert get_ig_bit(mac_anon) == get_ig_bit(mac_laa_bytes)
    assert get_ul_bit(mac_anon) == get_ul_bit(mac_laa_bytes)

    anonymize_pkt_macs(dhcp)
    mac_anon = dhcp.getlayer(DHCP).options[0][1][1:7]
    assert mac_anon != mac_laa_bytes
    assert get_ig_bit(mac_anon) == get_ig_bit(mac_laa_bytes)
    assert get_ul_bit(mac_anon) == get_ul_bit(mac_laa_bytes)


def test_anonymize_dhcp_uaa() -> None:
    """
    Test the function `anonymize_dhcp`,
    with universally administered addresses.
    """
    # Client hardware address
    dhcp = BOOTP(chaddr=mac_str_to_bytes(mac_uaa))
    anonymize_dhcp(dhcp)
    assert dhcp.chaddr[:3] == mac_uaa_bytes[:3]
    assert dhcp.chaddr[3:] != mac_uaa_bytes[3:]

    anonymize_pkt_macs(dhcp)
    assert dhcp.chaddr[:3] == mac_uaa_bytes[:3]
    assert dhcp.chaddr[3:] != mac_uaa_bytes[3:]


    # Option: Client Identifier
    dhcp /= DHCP(options=[("client_id", b"\x01" + mac_str_to_bytes(mac_uaa))])
    anonymize_dhcp(dhcp)
    mac_anon = dhcp.getlayer(DHCP).options[0][1][1:7]
    assert mac_anon[:3] == mac_uaa_bytes[:3]
    assert mac_anon[3:] != mac_uaa_bytes[3:]

    anonymize_pkt_macs(dhcp)
    mac_anon = dhcp.getlayer(DHCP).options[0][1][1:7]
    assert mac_anon[:3] == mac_uaa_bytes[:3]
    assert mac_anon[3:] != mac_uaa_bytes[3:]
