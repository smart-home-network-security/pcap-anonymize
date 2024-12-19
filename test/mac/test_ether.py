from scapy.layers.l2 import Ether
from pcap_anonymize.mac import anonymize_ether, anonymize_pkt_macs
from pcap_anonymize.mac.utils import get_ig_bit, get_ul_bit


### TEST CONSTANTS ###

mac_multicast = "01:00:00:00:00:00"
mac_multicast_bytes = b"\x01\x00\x00\x00\x00\x00"
mac_laa = "02:00:00:00:00:00"
mac_laa_bytes = b"\x02\x00\x00\x00\x00\x00"
mac_uaa = "00:11:22:33:44:55"
mac_uaa_bytes = b"\x00\x11\x22\x33\x44\x55"


### TEST FUNCTIONS ###

def test_anonymize_ether_multicast() -> None:
    """
    Test the function `anonymize_ether`,
    with multicast addresses.
    """
    ether_multicast = Ether(src=mac_multicast, dst=mac_multicast)
    anonymize_ether(ether_multicast)
    assert ether_multicast.src == mac_multicast
    assert ether_multicast.dst == mac_multicast

    anonymize_pkt_macs(ether_multicast)
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

    anonymize_pkt_macs(ether_laa)
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

    anonymize_pkt_macs(ether_laa)
    assert ether_laa.src.startswith(mac_uaa[:8])
    assert ether_laa.src[10:] != mac_uaa[10:]
    assert ether_laa.dst.startswith(mac_uaa[:8])
    assert ether_laa.dst[10:] != mac_uaa[10:]
