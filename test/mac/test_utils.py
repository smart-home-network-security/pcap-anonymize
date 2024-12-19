from pcap_anonymize.mac.utils import (
    mac_str_to_bytes, mac_bytes_to_str,
    get_ig_bit, get_ul_bit,
    anonymize_mac
)


### TEST CONSTANTS ###

mac_multicast = "01:00:00:00:00:00"
mac_multicast_bytes = b"\x01\x00\x00\x00\x00\x00"
mac_laa = "02:00:00:00:00:00"
mac_laa_bytes = b"\x02\x00\x00\x00\x00\x00"
mac_uaa = "00:11:22:33:44:55"
mac_uaa_bytes = b"\x00\x11\x22\x33\x44\x55"


### TEST FUNCTIONS ###

def test_mac_str_to_bytes() -> None:
    """
    Test the function `mac_str_to_bytes`,
    which converts a MAC address' string representation to bytes.
    """
    assert mac_str_to_bytes(mac_multicast) == mac_multicast_bytes
    assert mac_str_to_bytes(mac_laa) == mac_laa_bytes
    assert mac_str_to_bytes(mac_uaa) == mac_uaa_bytes


def test_mac_bytes_to_str() -> None:
    """
    Test the function `mac_bytes_to_str`,
    which converts a MAC address' bytes representation to a string.
    """
    assert mac_bytes_to_str(mac_multicast_bytes) == mac_multicast
    assert mac_bytes_to_str(mac_laa_bytes) == mac_laa
    assert mac_bytes_to_str(mac_uaa_bytes) == mac_uaa


def test_get_ig_bit() -> None:
    """
    Test the function `get_ig_bit`,
    both with string and bytes representations of MAC addresses.
    """
    # String representation
    assert get_ig_bit(mac_multicast) == 0b00000001
    assert get_ig_bit(mac_laa) == 0b00000000
    assert get_ig_bit(mac_uaa) == 0b00000000
    # Bytes representation
    assert get_ig_bit(mac_multicast_bytes) == 0b00000001
    assert get_ig_bit(mac_laa_bytes) == 0b00000000
    assert get_ig_bit(mac_uaa_bytes) == 0b00000000


def test_get_ul_bit() -> None:
    """
    Test the function `get_ul_bit`,
    both with string and bytes representations of MAC addresses.
    """
    # String representation
    assert get_ul_bit(mac_multicast) == 0b00000000
    assert get_ul_bit(mac_laa) == 0b00000010
    assert get_ul_bit(mac_uaa) == 0b00000000
    # Bytes representation
    assert get_ul_bit(mac_multicast_bytes) == 0b00000000
    assert get_ul_bit(mac_laa_bytes) == 0b00000010
    assert get_ul_bit(mac_uaa_bytes) == 0b00000000


def test_anonymize_mac_multicast() -> None:
    """
    Test the function `anonymize_mac`
    with a multicast MAC address.
    The MAC address should not be anonymized.
    """
    assert anonymize_mac(mac_multicast) == mac_multicast
    assert mac_str_to_bytes(anonymize_mac(mac_multicast_bytes)) == mac_multicast_bytes


def test_anonymize_mac_laa() -> None:
    """
    Test the function `anonymize_mac`
    with a locally administered MAC address.
    All bits should be anonymized except the I/G and U/L bits.
    """
    mac_laa_anon = anonymize_mac(mac_laa)
    assert mac_laa_anon != mac_laa
    assert get_ig_bit(mac_laa) == get_ig_bit(mac_laa_anon)
    assert get_ul_bit(mac_laa) == get_ul_bit(mac_laa_anon)

    mac_laa_bytes_anon = mac_str_to_bytes(anonymize_mac(mac_laa_bytes))
    assert mac_laa_bytes_anon != mac_laa_bytes
    assert get_ig_bit(mac_laa_bytes) == get_ig_bit(mac_laa_bytes_anon)
    assert get_ul_bit(mac_laa_bytes) == get_ul_bit(mac_laa_bytes_anon)


def test_anonymize_mac_uaa() -> None:
    """
    Test the function `anonymize_mac`
    with an universally administered MAC address.
    The 3 first bytes (vendor's OUI) should be kept,
    and the 3 last bytes should be anonymized.
    """
    mac_uaa_anon = anonymize_mac(mac_uaa)
    assert mac_uaa_anon.startswith(mac_uaa[:8])  # Vendor's OUI is kept
    assert mac_uaa_anon[10:] != mac_uaa[10:]     # Last 3 bytes are anonymized

    mac_uaa_bytes_anon = mac_str_to_bytes(anonymize_mac(mac_uaa_bytes))
    assert mac_uaa_bytes_anon[:3] == mac_uaa_bytes[:3]  # Vendor's OUI is kept
    assert mac_uaa_bytes_anon[3:] != mac_uaa_bytes[3:]  # Last 3 bytes are anonymized
