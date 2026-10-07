"""DNS probes use the tunnel source; they never select the management route."""
import ipaddress
import os
import socket
import struct


def probe(source, resolver):
    identifier = int.from_bytes(os.urandom(2), 'big')
    question = b'\x07example\x03com\x00' + struct.pack('!HH', 1, 1)
    request = struct.pack('!6H', identifier, 0x0100, 1, 0, 0, 0) + question
    try:
        source = str(ipaddress.IPv4Interface(source).ip)
        resolver = str(ipaddress.IPv4Address(resolver))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(2)
            sock.bind((source, 0))
            sock.connect((resolver, 53))
            sock.send(request)
            response = sock.recv(4096)
        ident, flags, questions, answers, _, _ = struct.unpack('!6H', response[:12])
        return (ident == identifier and bool(flags & 0x8000) and not flags & 0x7A0F
                and questions == 1 and answers > 0 and response[12:12 + len(question)] == question)
    except (OSError, ValueError, struct.error):
        return False


def choose(config, query=probe):
    for resolver in (config['dns'], config.get('dns_secondary')):
        if resolver and query(config['address'], resolver):
            return resolver
    return None
