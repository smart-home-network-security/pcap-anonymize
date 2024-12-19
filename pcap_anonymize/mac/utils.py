"""
Util functions for MAC address manipulation.
"""

from hashlib import sha256


BASE_HEX = 16
BYTE_ORDER = "big"

# Special, well-known MAC addresses
special_macs = [
    "00:00:00:00:00:00",         # Default
    b"\x00\x00\x00\x00\x00\x00", # Default, as bytes
    "ff:ff:ff:ff:ff:ff",         # Broadcast
    b"\xff\xff\xff\xff\xff\xff"  # Broadcast, as bytes
]


def mac_str_to_bytes(mac: str) -> bytes:
    """
    Convert a MAC address string representation
    to a bytes object.

    Args:
        mac (str): MAC address to convert
    Returns:
        bytes: MAC address as a bytes object
    """
    return bytes.fromhex(mac.replace(":", ""))


def mac_bytes_to_str(mac: bytes) -> str:
    """
    Convert a MAC address bytes object
    to its string representation.

    Args:
        mac (bytes): MAC address to convert
    Returns:
        str: MAC address as a string
    """
    return ":".join(f"{byte:02x}" for byte in mac)


def get_first_byte(mac: str | bytes) -> int:
    """
    Get the first byte of a MAC address.

    Args:
        mac (str | bytes): MAC address to get the first byte from
    Returns:
        int: first byte of the MAC address
    Raises:
        TypeError: if the MAC address is of an unsupported type
    """
    # Dispatch based on the type of the MAC address
    if isinstance(mac, str):
        return int(mac.split(":")[0], BASE_HEX)
    elif isinstance(mac, bytes):
        return int(mac[0])
    else:
        raise TypeError(f"Unsupported type for MAC address: {type(mac)}")


def get_ig_bit(mac: str | bytes) -> int:
    """
    Get the I/G bit of a given MAC address.

    Args:
        mac (str | bytes): MAC address to get the I/G bit from
    Returns:
        int: 8-bit integer with the I/G bit set to its corresponding value,
             and all other bits set to 0 
    Raises:
        TypeError: if the MAC address is of an unsupported type
    """
    ig_mask = 0b00000001
    return get_first_byte(mac) & ig_mask


def get_ul_bit(mac: str | bytes) -> int:
    """
    Get the U/L bit of a given MAC address.

    Args:
        mac (str | bytes): MAC address to get the U/L bit from
    Returns:
        int: 8-bit integer with the U/L bit set to its corresponding value,
             and all other bits set to 0 
    Raises:
        TypeError: if the MAC address is of an unsupported type
    """
    ul_mask = 0b00000010
    return get_first_byte(mac) & ul_mask


def anonymize_mac(mac: str) -> str:
    """
    Anonymize a given MAC address.

    Args:
        mac (str): MAC address to anonymize
    Returns:
        str: anonymized MAC address
    """
    # Special MAC address
    if mac in special_macs:
        return mac
    
    ### Classic MAC address

    ## I/G bit: first byte, least-significant bit
    # I/G bit = 0 ==> Unicast address
    # I/G bit = 1 ==> Multicast address
    ig_bit = get_ig_bit(mac)
    is_multicast = bool(ig_bit)  # True ==> Multicast, False ==> Unicast

    # Multicast address:
    # do not anonymize
    if is_multicast:
        if isinstance(mac, bytes):
            return mac_bytes_to_str(mac)
        elif isinstance(mac, str):
            return mac

    ## U/L bit: first byte, second least-significant bit
    # U/L bit = 0 ==> Universally administered address (UAA)
    # U/L bit = 1 ==> Locally administered address (LAA)
    ul_bit = get_ul_bit(mac)
    is_local = bool(ul_bit)  # True ==> LAA, False ==> UAA

    mac_bytes = mac if isinstance(mac, bytes) else mac_str_to_bytes(mac)

    ## Locally administered address
    if is_local:
        bit_mask = ig_bit | ul_bit

        # Compute SHA-256 hash of the MAC address
        mac_sha256 = sha256()
        for byte in mac_bytes:
            mac_sha256.update(byte.to_bytes(1, BYTE_ORDER))
        digest = mac_sha256.digest()

        first_byte = (digest[0] & 0b11111100) | bit_mask  # Keep I/G and U/L bits
        return f"{first_byte:02x}:" + ':'.join(f"{digest[i]:02x}" for i in range(1, 6))
    

    ## Universally administered address
    
    # Compute SHA-256 hash based on the three least-significant bytes
    mac_sha256 = sha256()
    for byte in mac_bytes[3:]:
        mac_sha256.update(byte.to_bytes(1, BYTE_ORDER))
    digest = mac_sha256.digest()

    # Keep OUI and anonymize the rest
    return (
        ':'.join(f"{byte:02x}" for byte in mac_bytes[:3]) +  # Keep OUI
        ':' +
        ':'.join(f"{digest[i]:02x}" for i in range(0, 3))  # Hashed last 3 bytes
    )
