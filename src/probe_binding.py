"""Bind health traffic to its explicit source, interface and optional policy."""
import ipaddress
import re
import socket


def bind_path(sock, source=None, interface=None, mark=None):
    # Validate everything before touching the socket. A failure must not leave
    # an unbound probe able to continue via a different/native uplink.
    if source is not None:
        if not isinstance(source, str):
            raise ValueError('Probe source must be an IPv4 string')
        source = str(ipaddress.IPv4Interface(source).ip)
    if interface is not None:
        if not isinstance(interface, str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface):
            raise ValueError('Invalid probe interface')
        if not hasattr(socket, 'SO_BINDTODEVICE'):
            raise OSError('Interface-bound probes are unavailable')
    if mark is not None:
        if type(mark) is not int or not 1 <= mark <= 0xffffffff:
            raise ValueError('Invalid probe routing mark')
        if not hasattr(socket, 'SO_MARK'):
            raise OSError('Policy-bound probes are unavailable')
    if source is not None:
        sock.bind((source, 0))
    if interface is not None:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b'\0')
    if mark is not None:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, mark)
