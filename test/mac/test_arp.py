from scapy.layers.l2 import ARP
from pcap_anonymize.mac import anonymize_arp, anonymize_pkt_macs
from pcap_anonymize.mac.utils import get_ig_bit, get_ul_bit


### TEST CONSTANTS ###

mac_multicast = "01:00:00:00:00:00"
mac_multicast_bytes = b"\x01\x00\x00\x00\x00\x00"
mac_laa = "02:00:00:00:00:00"
mac_laa_bytes = b"\x02\x00\x00\x00\x00\x00"
mac_uaa = "00:11:22:33:44:55"
mac_uaa_bytes = b"\x00\x11\x22\x33\x44\x55"


### TEST FUNCTIONS ###

def test_anonymize_arp_multicast() -> None:
    """
    Test the function `anonymize_arp`,
    with multicast addresses.
    """
    arp_multicast = ARP(hwsrc=mac_multicast, hwdst=mac_multicast)
    anonymize_arp(arp_multicast)
    assert arp_multicast.hwsrc == mac_multicast
    assert arp_multicast.hwdst == mac_multicast

    anonymize_pkt_macs(arp_multicast)
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

    anonymize_pkt_macs(arp_laa)
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

    anonymize_pkt_macs(arp_uaa)
    assert arp_uaa.hwsrc.startswith(mac_uaa[:8])
    assert arp_uaa.hwsrc[10:] != mac_uaa[10:]
    assert arp_uaa.hwdst.startswith(mac_uaa[:8])
    assert arp_uaa.hwdst[10:] != mac_uaa[10:]
