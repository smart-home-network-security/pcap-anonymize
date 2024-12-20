# pcap-anonymization

This Python package reads PCAP files,
and produces anonymized versions of the given files.
More precisely, the following fields are anonymized:
- Ethernet
  - Source MAC address
  - Destination MAC address
- ARP
  - Source hardware address
  - Destination hardware address
- DHCP
  - Client hardware address
  - Client Identifier option
- HTTP
  - All fields are removed, except the method and URI path.
  - Request parameters are removed
- CoAP
  - All fields are removed, except the type, code, and URI path.
- TP-Link Smart Home protocol (TCP port 9999)
  - The TCP payload is removed.


## Installation

### Dependencies
- [`scapy`](https://pypi.org/project/scapy)

### Retrieve from PyPI

```bash
pip install pcap-anonymize
```

## Usage

### CLI

```bash
pcap-anonymize [-i input] [-o output] [-d dir]
```

The program can be used either with a single input PCAP file,
or a directory containing multiple PCAP files.

Options for the former case are the following:
- `input`: path to a single input PCAP file
- `output`: path to a single output file.
  - If not specified, a new file is created in the same directory as the input file, with the name `<input>.anon.pcap`.

In the latter case, only the directory containing the PCAP files is provided.
For each PCAP file, its corresponding, anonymized output file will be created in the same directory,
with the suffix `anon.pcap`.


If no option is provided, the program stops directly.


### Library

#### Single input/output file
```python
from pcap_anonymize import anonymize_pcap

anonymize_pcap(
    input: os.PathLike,
    output: os.PathLike = None
)
```

#### Directory
```python
from pcap_anonymize import anonymize_pcaps_in_dir

anonymize_pcaps_in_dir(
    dir: os.PathLike
)
```
