"""
Anonymize the TP-Link Smart Home protocol,
running over TCP port 9999.
"""

from scapy.layers.inet import TCP


def anonymize_tplink(packet: TCP) -> None:
    """
    Anonymize a packet's TP-Link Smart Home protocol,
    by removing the payload.

    Args:
        packet (scapy.layers.inet.TCP): Packet to anonymize
    """
    packet.remove_payload()
