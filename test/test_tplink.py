from scapy.packet import Raw
from scapy.layers.inet import TCP
from pcap_anonymize.layers.tplink import anonymize_tplink


### TEST FUNCTIONS ###

def test_anonymize_tplink() -> None:
    """
    Test the function `anonymize_tplink`.
    """
    # Build dummy TP-Link Smart Home packet
    tcp = TCP(dport=9999)
    payload = Raw(load=b"abcdef")
    packet = tcp / payload

    anonymize_tplink(packet)

    # Check if payload was correctly deleted
    assert not packet.haslayer(Raw)
    assert not hasattr(packet, "load")
