from scapy.contrib.coap import CoAP
from pcap_anonymize.layers.coap import CoapFields, anonymize_coap


### TEST FUNCTIONS ###

def test_anonymize_coap() -> None:
    # Build CoAP layer
    options = [('Uri-Host', 'host'), ('Uri-Path', 'sensors'), ('Uri-Path', 'temperature')]
    coap = CoAP(type=0, code=1, msg_id=0x1234, token=b"token", options=options)

    anonymize_coap(coap)

    # Check remaining fields
    assert coap.type == 0
    assert coap.code == 1

    # Ensure other fields have been deleted
    for field in coap.fields:
        assert field in [f.value for f in CoapFields]
    for k, v in coap.getfieldval(CoapFields.OPTIONS.value):
        assert k == CoapFields.URI_PATH.value
        assert v in ["sensors", "temperature"]
