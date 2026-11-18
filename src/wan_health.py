"""Bound HTTPS reachability checks; no WAN DNS or device hostname is used."""
import json
import os
import re
import socket
import ssl
import sys
import time
from probe_binding import bind_path

ADDRESS = '1.1.1.1'
NAME = 'one.one.one.one'
# Hotspots behind several radio hops answer in 0.6-2 s; TCP + TLS + HTTP need
# about four round trips. The whole probe stays below the 8 s command timeout
# and the 10 s heartbeat freshness of its callers.
BUDGET = 7.0
PHASE = 4.0


DIAGNOSTIC_SOCKET = '/dev/log'


def _diagnose(interface, phase, error, status=None, error_number=None):
    """Best-effort local metadata only; never changes the reachability result."""
    try:
        known = ('SOCKET_SETUP', 'BIND', 'TCP_CONNECT', 'TLS_CONTEXT',
                 'TLS_HANDSHAKE', 'HTTP_SEND', 'HTTP_READ', 'HTTP_STATUS')
        record = {
            'v': 1, 'pid': os.getpid(), 'monotonic': round(time.monotonic(), 6),
            'interface': interface if interface in ('disabledrlwan', 'eth0', 'wgroadlink') else 'other',
            'phase': phase if phase in known else 'other',
            'error': error if type(error) is str and re.fullmatch(r'[A-Za-z_]{1,64}', error) else 'other',
            'status': status if type(status) is int and 100 <= status <= 999 else None,
            'errno': error_number if type(error_number) is int else None,
        }
        data = ('<28>RoadLinkHTTPS ' + json.dumps(record, separators=(',', ':'))).encode('ascii')
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as logger:
            logger.settimeout(0.02)
            logger.sendto(data, DIAGNOSTIC_SOCKET)
    except Exception:
        pass  # A missing/full local logger must never affect a probe.


def probe(interface, source=None, mark=None):
    started = time.monotonic()
    budget_end = started + BUDGET

    def limit():
        remaining = budget_end - time.monotonic()
        if remaining <= 0:
            raise TimeoutError('HTTPS probe budget')
        return min(PHASE, remaining)

    phase = 'SOCKET_SETUP'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(limit())
            phase = 'BIND'
            bind_path(sock, source, interface, mark)
            phase = 'TCP_CONNECT'
            sock.connect((ADDRESS, 443))
            phase = 'TLS_CONTEXT'
            context = ssl.create_default_context()
            phase = 'TLS_HANDSHAKE'
            sock.settimeout(limit())
            with context.wrap_socket(sock, server_hostname=NAME) as secure:
                phase = 'HTTP_SEND'
                secure.sendall(b'HEAD / HTTP/1.1\r\nHost: one.one.one.one\r\nConnection: close\r\n\r\n')
                # TLS records may split a valid status line at any byte.
                # All reads share one deadline inside the probe budget.
                phase = 'HTTP_READ'
                deadline = time.monotonic() + limit()
                status = b''
                while b'\r\n' not in status and len(status) < 1024:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError('HTTPS status-line deadline')
                    secure.settimeout(remaining)
                    part = secure.recv(1024 - len(status))
                    if not part:
                        break
                    status += part
                first = status.split(b'\r\n', 1)[0]
                match = re.fullmatch(rb'HTTP/1\.[01] ([0-9]{3})(?: [\x20-\x7e]*)?', first) if b'\r\n' in status else None
                healthy = bool(match and 200 <= int(match.group(1)) < 400 and time.monotonic() < deadline)
        if not healthy:
            cause = 'HTTP_STATUS_UNHEALTHY' if match else 'HTTP_STATUS_INVALID'
            if match and 200 <= int(match.group(1)) < 400:
                cause = 'HTTP_STATUS_LATE'
            _diagnose(interface, 'HTTP_STATUS', cause, int(match.group(1)) if match else None)
        elapsed = round((time.monotonic() - started) * 1000)
        return {'healthy': healthy, 'latency_ms': elapsed, 'score': max(1, 100 - elapsed // 20) if healthy else 0}
    except (OSError, ValueError, ssl.SSLError) as error:
        _diagnose(interface, phase, type(error).__name__, error_number=getattr(error, 'errno', None))
        return {'healthy': False, 'latency_ms': None, 'score': 0}


if __name__ == '__main__':
    if sys.argv[1] != 'disabledrlwan': raise ValueError('Unexpected probe interface')
    print(json.dumps(probe(sys.argv[1])))
