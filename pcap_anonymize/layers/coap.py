"""
Anonymize CoAP packets.
"""

from enum import Enum
from scapy.contrib.coap import CoAP


class CoapFields(Enum):
    """
    CoAP fields.
    """
    TYPE     = "type"
    CODE     = "code"
    OPTIONS  = "options"
    URI_PATH = "Uri-Path"


def anonymize_coap(coap: CoAP) -> None:
    """
    Anonymize a packet's CoAP layer.

    Args:
        coap (scapy.contrib.coap.CoAP): CoAP layer to anonymize
    """
    # Remove all fields other than type and code
    for field in coap.fields.copy():
        if field not in [f.value for f in CoapFields]:
            delattr(coap, field)

    # Remove all options other than Uri-Path
    options = coap.getfieldval(CoapFields.OPTIONS.value)
    new_options = []
    for k, v in options:
        if k == CoapFields.URI_PATH.value:
            new_options.append((k, v))
    coap.setfieldval(CoapFields.OPTIONS.value, new_options)
