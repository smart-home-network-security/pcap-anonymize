# Scapy
from scapy.packet import Packet
from scapy.layers.inet import TCP
from scapy.contrib.coap import CoAP

# Custom
from .http import get_http_layer, anonymize_http
from .coap import anonymize_coap
from .tplink import anonymize_tplink



def anonymize_app_layer(packet: Packet) -> None:
    """
    Anonymize a packet's application layer.

    Args:
        packet (scapy.Packet): packet to anonymize
    """
    # HTTP layer
    try:
        anonymize_http(get_http_layer(packet))
    except AttributeError:
        pass

    # CoAP layer
    try:
        anonymize_coap(packet.getlayer(CoAP))
    except AttributeError:
        pass

    # TP-Link Smart Home protocol layer
    # (i.e. TCP port 9999)
    try:
        tcp = packet.getlayer(TCP)
        sport = tcp.getfieldval("sport")
        dport = tcp.getfieldval("dport")
        if sport == 9999 or dport == 9999:
            anonymize_tplink(tcp)
    except AttributeError:
        pass
