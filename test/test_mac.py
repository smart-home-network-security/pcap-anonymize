from scapy.layers.l2 import Ether, ARP
from scapy.layers.dhcp import BOOTP, DHCP
from pcap_anonymize.layers.mac import (
    mac_str_to_bytes, mac_bytes_to_str,
    get_ig_bit, get_ul_bit,
    anonymize_mac,
    anonymize_ether,
    anonymize_arp,
    anonymize_dhcp
)


### TEST CONSTANTS ###

mac_multicast = "01:00:00:00:00:00"
mac_multicast_bytes = b"\x01\x00\x00\x00\x00\x00"
mac_laa = "02:00:00:00:00:00"
mac_laa_bytes = b"\x02\x00\x00\x00\x00\x00"
mac_uaa = "00:11:22:33:44:55"
mac_uaa_bytes = b"\x00\x11\x22\x33\x44\x55"


### TEST FUNCTIONS ###

def test_mac_str_to_bytes() -> None:
    """
    Test the function `mac_str_to_bytes`,
    which converts a MAC address' string representation to bytes.
    """
    assert mac_str_to_bytes(mac_multicast) == mac_multicast_bytes
    assert mac_str_to_bytes(mac_laa) == mac_laa_bytes
    assert mac_str_to_bytes(mac_uaa) == mac_uaa_bytes


def test_mac_bytes_to_str() -> None:
    """
    Test the function `mac_bytes_to_str`,
    which converts a MAC address' bytes representation to a string.
    """
    assert mac_bytes_to_str(mac_multicast_bytes) == mac_multicast
    assert mac_bytes_to_str(mac_laa_bytes) == mac_laa
    assert mac_bytes_to_str(mac_uaa_bytes) == mac_uaa


def test_get_ig_bit() -> None:
    """
    Test the function `get_ig_bit`.
    """
    assert get_ig_bit("00:00:00:00:00:00") == 0b00000000
    assert get_ig_bit("01:00:00:00:00:00") == 0b00000001
    assert get_ig_bit("12:34:56:78:9a:bc") == 0b00000000


def test_get_ul_bit() -> None:
    """
    Test the function `get_ul_bit`.
    """
    assert get_ul_bit("00:00:00:00:00:00") == 0b00000000
    assert get_ul_bit("02:00:00:00:00:00") == 0b00000010
    assert get_ul_bit("12:34:56:78:9a:bc") == 0b00000010


def test_anonymize_mac_multicast() -> None:
    """
    Test the function `anonymize_mac`
    with a multicast MAC address.
    The MAC address should not be anonymized.
    """
    assert anonymize_mac(mac_multicast) == mac_multicast


def test_anonymize_mac_laa() -> None:
    """
    Test the function `anonymize_mac`
    with a locally administered MAC address.
    All bits should be anonymized except the I/G and U/L bits.
    """
    mac_laa_anon = anonymize_mac(mac_laa)
    assert mac_laa_anon != mac_laa
    # Verify I/G and U/L bits
    assert get_ig_bit(mac_laa) == get_ig_bit(mac_laa_anon)
    assert get_ul_bit(mac_laa) == get_ul_bit(mac_laa_anon)


def test_anonymize_mac_uaa() -> None:
    """
    Test the function `anonymize_mac`
    with an universally administered MAC address.
    The 3 first bytes (vendor's OUI) should be kept,
    and the 3 last bytes should be anonymized.
    """
    mac_uaa_anon = anonymize_mac(mac_uaa)
    assert mac_uaa_anon.startswith(mac_uaa[:8])  # Vendor's OUI is kept
    assert mac_uaa_anon[10:] != mac_uaa[10:]     # Last 3 bytes are anonymized


def test_anonymize_ether_multicast() -> None:
    """
    Test the function `anonymize_ether`,
    with multicast addresses.
    """
    ether_multicast = Ether(src=mac_multicast, dst=mac_multicast)
    anonymize_ether(ether_multicast)
    assert ether_multicast.src == mac_multicast
    assert ether_multicast.dst == mac_multicast


def test_anonymize_ether_laa() -> None:
    """
    Test the function `anonymize_ether`,
    with locally administered addresses.
    """
    ether_laa = Ether(src=mac_laa, dst=mac_laa)
    anonymize_ether(ether_laa)
    assert ether_laa.src != mac_laa
    assert get_ig_bit(ether_laa.src) == get_ig_bit(mac_laa)
    assert get_ul_bit(ether_laa.src) == get_ul_bit(mac_laa)
    assert ether_laa.dst != mac_laa
    assert get_ig_bit(ether_laa.dst) == get_ig_bit(mac_laa)
    assert get_ul_bit(ether_laa.dst) == get_ul_bit(mac_laa)


def test_anonymize_ether_uaa() -> None:
    """
    Test the function `anonymize_ether`,
    with universally administered addresses.
    """
    ether_laa = Ether(src=mac_uaa, dst=mac_uaa)
    anonymize_ether(ether_laa)
    assert ether_laa.src.startswith(mac_uaa[:8])
    assert ether_laa.src[10:] != mac_uaa[10:]
    assert ether_laa.dst.startswith(mac_uaa[:8])
    assert ether_laa.dst[10:] != mac_uaa[10:]


def test_anonymize_arp_multicast() -> None:
    """
    Test the function `anonymize_arp`,
    with multicast addresses.
    """
    arp_multicast = ARP(hwsrc=mac_multicast, hwdst=mac_multicast)
    anonymize_arp(arp_multicast)
    assert arp_multicast.hwsrc == mac_multicast
    assert arp_multicast.hwdst == mac_multicast


def test_anonymize_arp_laa() -> None:
    """
    Test the function `anonymize_arp`,
    with locally administered addresses.
    """
    arp_laa = ARP(hwsrc=mac_laa, hwdst=mac_laa)
    anonymize_arp(arp_laa)
    assert arp_laa.hwsrc != mac_laa
    assert get_ig_bit(arp_laa.hwsrc) == get_ig_bit(mac_laa)
    assert get_ul_bit(arp_laa.hwsrc) == get_ul_bit(mac_laa)
    assert arp_laa.hwdst != mac_laa
    assert get_ig_bit(arp_laa.hwdst) == get_ig_bit(mac_laa)
    assert get_ul_bit(arp_laa.hwdst) == get_ul_bit(mac_laa)


def test_anonymize_arp_uaa() -> None:
    """
    Test the function `anonymize_arp`,
    with universally administered addresses.
    """
    arp_uaa = ARP(hwsrc=mac_uaa, hwdst=mac_uaa)
    anonymize_arp(arp_uaa)
    assert arp_uaa.hwsrc.startswith(mac_uaa[:8])
    assert arp_uaa.hwsrc[10:] != mac_uaa[10:]
    assert arp_uaa.hwdst.startswith(mac_uaa[:8])
    assert arp_uaa.hwdst[10:] != mac_uaa[10:]


# def test_anonymize_dhcp_multicast() -> None:
#     """
#     Test the function `anonymize_dhcp`,
#     with multicast addresses.
#     """
#     dhcp = BOOTP(chaddr=mac_multicast)
#     anonymize_dhcp(dhcp)
#     assert dhcp.chaddr == mac_multicast
