from scapy.layers.inet import TCP
from scapy.layers.http import HTTPRequest, HTTPResponse
from pcap_anonymize.layers.http import (
    HttpFields,
    get_http_layer,
    anonymize_http
)


### TEST CONSTANTS ###

ENCODING = "utf-8"

http_request = HTTPRequest(
    Method="GET",
    Path="/index.html"
)
http_response = HTTPResponse(
    Status_Code="200",
    Reason_Phrase="OK"
)


### TEST FUNCTIONS ###

def test_get_http_layer_request() -> None:
    """
    Test the function `get_http_layer`,
    with an HTTP Request packet.
    """
    packet = TCP(dport=80) / http_request
    http = get_http_layer(packet)
    assert http == http_request
    assert http.getfieldval(HttpFields.METHOD.value).decode(ENCODING) == "GET"
    assert http.getfieldval(HttpFields.PATH.value).decode(ENCODING) == "/index.html"


def test_get_http_layer_request_indirect() -> None:
    """
    Test the function `get_http_layer`,
    with an HTTP Request packet
    which is not directly accessible by scapy.
    """
    packet = TCP(dport=8800) / http_request
    http = get_http_layer(packet)
    assert isinstance(http, HTTPRequest)
    assert http == http_request
    assert http.getfieldval(HttpFields.METHOD.value).decode(ENCODING) == "GET"
    assert http.getfieldval(HttpFields.PATH.value).decode(ENCODING) == "/index.html"


def test_get_http_layer_response() -> None:
    """
    Test the function `get_http_layer`,
    with an HTTP Response packet.
    """
    packet = TCP(dport=80) / http_response
    http = get_http_layer(packet)
    assert http == http_response
    assert http.getfieldval("Status_Code").decode(ENCODING) == "200"
    assert http.getfieldval("Reason_Phrase").decode(ENCODING) == "OK"


def test_get_http_layer_response_indirect() -> None:
    """
    Test the function `get_http_layer`,
    with an HTTP Response packet
    which is not directly accessible by scapy.
    """
    packet = TCP(dport=8800) / http_response
    http = get_http_layer(packet)
    assert isinstance(http, HTTPResponse)
    assert http == http_response
    assert http.getfieldval("Status_Code").decode(ENCODING) == "200"
    assert http.getfieldval("Reason_Phrase").decode(ENCODING) == "OK"


def test_anonymize_http_request() -> None:
    """
    Test the function `anonymize_http`,
    with an HTTP Request packet.
    """
    packet = TCP(dport=80) / http_request
    http = get_http_layer(packet)
    anonymize_http(http)
    assert http.getfieldval(HttpFields.METHOD.value).decode(ENCODING) == "GET"
    assert http.getfieldval(HttpFields.PATH.value).decode(ENCODING) == "/index.html"
    
    # Ensure other fields have been deleted
    for field in http.fields:
        assert field == HttpFields.METHOD.value or field == HttpFields.PATH.value
    

def test_anonymize_http_request_indirect() -> None:
    """
    Test the function `anonymize_http`,
    with an HTTP Request packet.
    """
    packet = TCP(dport=8800) / http_request
    http = get_http_layer(packet)
    anonymize_http(http)
    assert http.getfieldval(HttpFields.METHOD.value).decode(ENCODING) == "GET"
    assert http.getfieldval(HttpFields.PATH.value).decode(ENCODING) == "/index.html"
    
    # Ensure other fields have been deleted
    for field in http.fields:
        assert field == HttpFields.METHOD.value or field == HttpFields.PATH.value


def test_anonymize_http_response() -> None:
    """
    Test the function `anonymize_http`,
    with an HTTP Response packet.
    """
    packet = TCP(dport=80) / http_response
    http = get_http_layer(packet)
    anonymize_http(http)
    for field in http.fields:
        assert field == HttpFields.METHOD.value or field == HttpFields.PATH.value


def test_anonymize_http_response_indirect() -> None:
    """
    Test the function `anonymize_http`,
    with an HTTP Response packet.
    """
    packet = TCP(dport=8800) / http_response
    http = get_http_layer(packet)
    anonymize_http(http)
    for field in http.fields:
        assert field == HttpFields.METHOD.value or field == HttpFields.PATH.value

