import sys
import os
import pytest

# Add src directory to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'src')))

from http_parser import HTTPParser

def test_http_parser_valid_host():
    # Construct a valid HTTP GET request
    request = (
        b"GET /index.html HTTP/1.1\r\n"
        b"Host: example.com\r\n"
        b"User-Agent: Mozilla/5.0\r\n\r\n"
    )
    
    host = HTTPParser.extract_host(request)
    assert host == "example.com"

def test_http_parser_case_insensitive_host():
    # Host header with different casing and spacing
    request = (
        b"POST /api/login HTTP/1.1\r\n"
        b"hoST:  auth.myservice.org  \r\n"
        b"Content-Length: 0\r\n\r\n"
    )
    
    host = HTTPParser.extract_host(request)
    assert host == "auth.myservice.org"

def test_http_parser_invalid_request():
    # Not an HTTP request method
    request = (
        b"INVALID_METHOD / HTTP/1.1\r\n"
        b"Host: example.com\r\n\r\n"
    )
    assert HTTPParser.extract_host(request) is None
