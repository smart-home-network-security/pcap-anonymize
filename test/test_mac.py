from pcap_anonymize.layers.mac import get_ig_bit, get_ul_bit, anonymize_mac

# Number of random MAC addresses to generate per unit test
N_TESTS = 5


### TEST FUNCTIONS ###

def test_get_ig_bit():
    """
    Test the function `get_ig_bit`.
    """
    assert get_ig_bit("00:00:00:00:00:00") == 0b00000000
    assert get_ig_bit("01:00:00:00:00:00") == 0b00000001
    assert get_ig_bit("12:34:56:78:9a:bc") == 0b00000000


def test_get_ul_bit():
    """
    Test the function `get_ul_bit`.
    """
    assert get_ul_bit("00:00:00:00:00:00") == 0b00000000
    assert get_ul_bit("02:00:00:00:00:00") == 0b00000010
    assert get_ul_bit("12:34:56:78:9a:bc") == 0b00000010


def test_anonymize_mac_multicast():
    """
    Test the function `anonymize_mac`
    with a multicast MAC address.
    The MAC address should not be anonymized.
    """
    mac_multicast = "01:00:00:00:00:00"
    assert anonymize_mac(mac_multicast) == mac_multicast


def test_anonymize_mac_laa():
    """
    Test the function `anonymize_mac`
    with a locally administered MAC address.
    All bits should be anonymized except the I/G and U/L bits.
    """
    mac_laa = "02:00:00:00:00:00"

    # Generate N anonymized MAC addresses,
    # and verify they are correct
    for _ in range(N_TESTS):
        mac_laa_anon = anonymize_mac(mac_laa)
        assert mac_laa_anon != mac_laa
        # Verify I/G and U/L bits
        assert get_ig_bit(mac_laa) == get_ig_bit(mac_laa_anon)
        assert get_ul_bit(mac_laa) == get_ul_bit(mac_laa_anon)
