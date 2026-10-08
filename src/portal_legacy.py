"""Legacy HTTP 204/redirect signals; no login, redirect following or ONLINE grant."""
import ipaddress
import socket
from urllib.parse import urljoin
import capport
from portal_dns import remaining, resolve
from portal_fetch import receive
from probe_binding import bind_path

HOST = 'connectivitycheck.gstatic.com'
URL = 'http://' + HOST + '/generate_204'


def signal(value, lease, vehicle_subnet, transit_subnet):
    status = value['status']
    if status == 204 and not value['body']:
        return {'state': 'HTTP_UNRESTRICTED_HINT'}
    if status in (301, 302, 303, 307, 308) and value['location']:
        portal = capport.uri(urljoin(URL, value['location']), legacy_http=True)
        from urllib.parse import urlsplit
        try: address = str(ipaddress.IPv4Address(urlsplit(portal).hostname))
        except ValueError: address = None
        if address is not None and not capport.allowed_address(address, lease, vehicle_subnet, transit_subnet):
            raise ValueError('Protected legacy portal redirect')
        return {'state': 'LEGACY_CAPTIVE', 'url': portal}
    if status == 200 and value['body'] and value['content_type'].split(';', 1)[0].strip().lower() == 'text/html':
        return {'state': 'POSSIBLE_CAPTIVE', 'url': URL}
    return {'state': 'INCONCLUSIVE'}


def probe(lease, resolvers, vehicle_subnet, transit_subnet, interface, mark, check, permit, deadline):
    source = str(ipaddress.IPv4Interface(lease['address']).ip)
    addresses = resolve(HOST, resolvers, source, interface, mark, check, permit, deadline)['addresses']
    if not all(capport.allowed_address(address, lease, vehicle_subnet, transit_subnet) for address in addresses):
        raise ValueError('Protected legacy probe destination')
    # Fixed path, no unique device header, no cookies, no credentials. A login
    # page is never fetched/accepted by this HTTP detection routine.
    request = ('GET /generate_204 HTTP/1.1\r\nHost: ' + HOST +
               '\r\nAccept: text/html\r\nAccept-Encoding: identity\r\nConnection: close\r\n\r\n').encode('ascii')
    for address in addresses:
        check()
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(remaining(deadline, check))
                bind_path(sock, source, interface, mark)
                with permit(sock, address, 80, 'tcp'):
                    sock.settimeout(remaining(deadline, check))
                    sock.connect((address, 80))
                    sock.settimeout(remaining(deadline, check))
                    sock.sendall(request)
                    value = receive(sock, check, deadline)
                    check()
                    return signal(value, lease, vehicle_subnet, transit_subnet)
        except OSError:
            check()
    raise ValueError('Legacy portal probe unavailable')
