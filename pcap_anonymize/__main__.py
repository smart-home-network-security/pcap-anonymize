import argparse
from .pcap_anonymize import anonymize_pcap, anonymize_pcaps_in_dir


### MAIN FUNCTION ###
def main() -> None:
    parser = argparse.ArgumentParser(description="Anonymize a PCAP traffic capture.")
    parser.add_argument("-i", "--input", type=str, help="Path to the input PCAP file.")
    parser.add_argument("-o", "--output", type=str, help="Path to the output PCAP file.")
    parser.add_argument("-d", "--dir", type=str, help="Path to the directory containing the input PCAP files.")
    args = parser.parse_args()

    if args.dir:
        anonymize_pcaps_in_dir(args.dir)
    else:
        anonymize_pcap(args.input, args.output)


### ENTRY POINT ###
if __name__ == "__main__":
    main()
