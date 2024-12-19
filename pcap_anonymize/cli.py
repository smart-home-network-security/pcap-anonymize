import os
import argparse
from .pcap_anonymize import anonymize_pcap


def main() -> None:
    """
    Main function for the CLI.
    """
    parser = argparse.ArgumentParser(description="Anonymize a PCAP traffic capture.")
    parser.add_argument("input", type=os.PathLike, help="Path to the input PCAP file.")
    parser.add_argument("-o", "--output", type=os.PathLike, help="Path to the output PCAP file.")
    args = parser.parse_args()

    anonymize_pcap(args.input, args.output)
