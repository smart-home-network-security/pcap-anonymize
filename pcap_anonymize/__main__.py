import os
import argparse
from .pcap_anonymize import anonymize_pcap


### MAIN FUNCTION ###
def main() -> None:
    parser = argparse.ArgumentParser(description="Anonymize a PCAP traffic capture.")
    parser.add_argument("input", type=str, help="Path to the input PCAP file.")
    parser.add_argument("-o", "--output", type=str, help="Path to the output PCAP file.")
    args = parser.parse_args()

    anonymize_pcap(args.input, args.output)


### ENTRY POINT ###
if __name__ == "__main__":
    main()
