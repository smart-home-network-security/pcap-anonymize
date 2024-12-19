"""
Test the package with PCAP traces.
"""

import os
import glob
from pathlib import Path
from pcap_anonymize import anonymize_pcap, anonymize_pcaps_in_dir


### TEST CONSTANTS ###

dir_self = os.path.dirname(os.path.abspath(__file__))
dir_traces = os.path.join(dir_self, "traces")


### TEST FUNCTIONS ###

def test_anonymize_pcap_http(tmp_path: Path) -> None:
    """
    Test the package with a PCAP trace containing HTTP packets.

    Args:
        tmp_path (pathlib.Path): temporary directory to store the output traces
    """
    input = os.path.join(dir_traces, "http.pcap")
    output = os.path.join(tmp_path, "http.anon.pcap")
    anonymize_pcap(input, output)
    assert os.path.exists(input)
    assert os.path.exists(output)


def test_anonymize_pcap_dhcp(tmp_path: Path) -> None:
    """
    Test the package with a PCAP trace containing DHCP packets.

    Args:
        tmp_path (pathlib.Path): temporary directory to store the output traces
    """
    input = os.path.join(dir_traces, "dhcp.pcap")
    output = os.path.join(tmp_path, "dhcp.anon.pcap")
    anonymize_pcap(input, output)
    assert os.path.exists(input)
    assert os.path.exists(output)


def test_anonymize_pcap_tplink(tmp_path: Path) -> None:
    """
    Test the package with a PCAP trace containing
    TP-Link Smart Home protocol packets.

    Args:
        tmp_path (pathlib.Path): temporary directory to store the output traces
    """
    input = os.path.join(dir_traces, "tplink.pcap")
    output = os.path.join(tmp_path, "tplink.anon.pcap")
    anonymize_pcap(input, output)
    assert os.path.exists(input)
    assert os.path.exists(output)


def test_anonymize_pcaps_in_dir() -> None:
    """
    Test the package with a directory containing PCAP traces.
    """
    input_traces = glob.glob(os.path.join(dir_traces, "*.pcap"))
    anonymize_pcaps_in_dir(dir_traces)
    output_traces = glob.glob(os.path.join(dir_traces, "*.anon.pcap"))
    assert len(output_traces) == len(input_traces)

    # Clean up
    for output_trace in output_traces:
        os.remove(output_trace)
