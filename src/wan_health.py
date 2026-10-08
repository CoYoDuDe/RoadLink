"""Bound HTTPS reachability checks; no WAN DNS or device hostname is used."""
import json
import socket
import ssl
import sys
import time
from probe_binding import bind_path

ADDRESS = '1.1.1.1'
NAME = 'one.one.one.one'


def probe(interface, source=None, mark=None):
    started = time.monotonic()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(2)
            bind_path(sock, source, interface, mark)
            sock.connect((ADDRESS, 443))
            with ssl.create_default_context().wrap_socket(sock, server_hostname=NAME) as secure:
                secure.sendall(b'HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n')
                status = secure.recv(1024).split(b'\r\n', 1)[0].split()
                healthy = len(status) >= 2 and 200 <= int(status[1]) < 400
        elapsed = round((time.monotonic() - started) * 1000)
        return {'healthy': healthy, 'latency_ms': elapsed, 'score': max(1, 100 - elapsed // 20) if healthy else 0}
    except (OSError, ValueError, ssl.SSLError):
        return {'healthy': False, 'latency_ms': None, 'score': 0}


if __name__ == '__main__':
    if sys.argv[1] != 'disabledrlwan': raise ValueError('Unexpected probe interface')
    print(json.dumps(probe(sys.argv[1])))
