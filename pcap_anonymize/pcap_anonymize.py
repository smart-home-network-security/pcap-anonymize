"""
Anonymize all packets in a PCAP file.
"""

import os
import glob
from pathlib import Path
import logging
from scapy.all import Packet, sniff, wrpcap
# Packet layers
from .mac import anonymize_pkt_macs
from .app_layer import anonymize_app_layer


### GLOBAL VARIABLES ###

i = 1
packets = []

# Logging configuration
logger = logging.getLogger("pcap_anonymize")


### FUNCTIONS ###

def rebuild_packet(packet: Packet) -> Packet:
    """
    Rebuild a packet:
    recompute its lengths and checksums.

    Args:
        packet (scapy.Packet): scapy packet to rebuild
    Returns:
        scapy.Packet: rebuilt packet
    """
    fields_to_delete = ["len", "chksum"]

    for layer_class in packet.layers():
        layer = packet.getlayer(layer_class)
        for field in fields_to_delete:
            try:
                delattr(layer, field)
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
    global i, packets

    logger.debug(f"Packet #{i}: {packet.summary()}")

    # Anonymize MAC addresses
    anonymize_pkt_macs(packet)

    # Anonymize application layer
    anonymize_app_layer(packet)

    # Recompute packet checksums
    packet = rebuild_packet(packet)

    packets.append(packet)
    i += 1


def anonymize_pcap(input: os.PathLike, output: os.PathLike = None) -> None:
    """
    Anonymize all packets in a PCAP file.

    Args:
        input: path to the input PCAP file
        output: path to the output PCAP file.
                If None, create a new file having the same name as the input file with the suffix '.anon.pcap'.
    """
    global i, packets

    if output is None:
        output = str(Path(input).with_suffix(".anon.pcap"))

    # Read and anonymize packets from the input file
    sniff(offline=input, prn=anonymize_packet, store=False)

    # Write anonymized packets to the output file
    wrpcap(output, packets)

    # Reset global variables
    i = 1
    packets = []


def anonymize_pcaps_in_dir(dir: os.PathLike) -> None:
    """
    Anonymize all PCAP files in a directory.

    Args:
        dir: path to the directory containing the PCAP files
    """
    for pcap_file in glob.glob(os.path.join(dir, "*.pcap")):

        # Skip traces already anonymized
        if pcap_file.endswith(".anon.pcap"):
            continue

        anonymize_pcap(pcap_file, None)
