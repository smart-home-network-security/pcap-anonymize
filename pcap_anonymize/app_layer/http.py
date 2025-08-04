"""
Anonymize HTTP packets.
"""

from enum import Enum
import logging
from scapy.all import Packet, Raw
from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse


ENCODING = "utf-8"
logger = logging.getLogger("pcap_anonymize")


class HttpFields(Enum):
    """
    HTTP fields.
    """
    METHOD = "Method"
    PATH   = "Path"


def get_http_layer(packet: Packet) -> HTTP:
    """
    Get the HTTP layer from a packet.

    Args:
        packet (scapy.Packet): packet to get the HTTP layer from
    Returns:
        (scapy.HTTP): HTTP layer
    Raises:
        AttributeError: if the HTTP layer could not be found in the packet
    """
    ## Get HTTP layer directly
    # HTTP Request
    http = packet.getlayer(HTTPRequest)
    if http is not None:
        return http
    # HTTP Response
    http = packet.getlayer(HTTPResponse)
    if http is not None:
        return http
    
    # HTTP layer could not be retrieved directly.
    # Try to get it from the Raw layer.
    
    raw_load = packet.getlayer(Raw).getfieldval("load")
    try:
        http = HTTPRequest(raw_load)
        if http.haslayer(HTTPRequest):
            return http
    except ValueError:
        pass

    try:
        http = HTTPResponse(raw_load)
        if http.haslayer(HTTPResponse):
            return http
    except ValueError:
        pass
 
    raise AttributeError(f"HTTP layer not found in packet {packet.summary()}")


def anonymize_http(http: HTTP) -> None:
    """
    Anonymize a packet's HTTP layer.

    Args:
        http (scapy.HTTP): HTTP layer to anonymize
    """
    # Remove request parameters
    if http.haslayer(HTTPRequest):

        # Retrieve Path field
        try:
            path_bytes: bytes = http.getfieldval(HttpFields.PATH.value)
        except AttributeError:
            # HTTP packet does not contain the `Path` field
            logger.warning(f"Field {HttpFields.PATH.value} not found in HTTP layer {http.summary()}")
            pass

        # Decode Path field
        try:
            path_str: str = path_bytes.decode(ENCODING)
        except UnicodeDecodeError:
            # `Path` field is not encoded in UTF-8
            logger.warning(f"Field {HttpFields.PATH.value} in HTTP layer not encoded with {ENCODING}: {path_bytes}")
            pass
        else:
            path_new = path_str.split("?")[0]  # Remove query parameters
            path_new_encoded = path_new.encode(ENCODING)  # Re-encode the path
            http.setfieldval(HttpFields.PATH.value, path_new_encoded)


    # Remove all fields other than Method and Path
    for field in http.fields.copy():
        if field != HttpFields.METHOD.value and field != HttpFields.PATH.value:
            delattr(http, field)
