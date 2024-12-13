"""
Anonymize all packets in a PCAP file.
"""

import os
from pathlib import Path
from scapy.all import Packet, sniff, wrpcap
from scapy.layers.l2 import Ether, ARP
# Packet layers
from .layers.mac import anonymize_ether, anonymize_arp


### GLOBAL VARIABLES ###

packets = []



### FUNCTIONS ###

def recompute_checksums(packet: Packet) -> Packet:
    """
    Recompute a given packet's checksums.

    Args:
        packet (scapy.Packet): scapy packet to recompute checksums for
    Returns:
        (scapy.Packet): packet with recomputed checksums
    """
    for layer_class in packet.layers():
        layer = packet.getlayer(layer_class)
        try:
            delattr(layer, "chksum")
        except AttributeError:
            pass
        
    return packet.__class__(bytes(packet))


def anonymize_packet(packet: Packet) -> None:
    """
    Anonymize a packet,
    and append the anonymized packet to the global list 'packets'.

    Args:
        packet: scapy packet to anonymize
    """
    global packets

    # Anonymize MAC addresses
    try:
        anonymize_ether(packet.getlayer(Ether))
    except AttributeError:
        pass
    
    # Anonymize MAC addresses in ARP packets
    try:
        anonymize_arp(packet.getlayer(ARP))
    except AttributeError:
        pass

    # Recompute packet checksums
    packet = recompute_checksums(packet)

    packets.append(packet)


def anonymize_pcap(input: os.PathLike, output: os.PathLike = None) -> None:
    """
    Anonymize all packets in a PCAP file.

    Args:
        input: path to the input PCAP file
        output: path to the output PCAP file.
                If None, create a new file having the same name as the input file with the suffix '.anonymized.pcap'.
    """
    if output is None:
        output = str(Path(input).with_suffix('.anonymized.pcap'))

    # Read and anonymize packets from the input file
    sniff(offline=input, prn=anonymize_packet, store=False)

    # Write anonymized packets to the output file
    wrpcap(output, packets)
