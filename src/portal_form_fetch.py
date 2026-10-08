"""Read-only portal HTML through an owned WAN context; never grants Internet.

Results, including session URLs and HTML, are transient review input. Do not
persist or log them. This fetcher does not execute scripts, accept terms, send
credentials, collect cookies or declare a successful login.
"""
import ipaddress
import re
import socket
import ssl
from urllib.parse import urljoin, urlsplit
import capport
import portal_access
import portal_origins
from portal_dns import remaining, resolve
from portal_fetch import receive
from probe_binding import bind_path

MAX_BODY = 65536
MAX_WIRE = 98304


def origin(url):
    parts = urlsplit(capport.uri(url, legacy_http=True))
    return portal_origins.origin(parts.scheme + '://' + parts.netloc)


def request(url):
    parts = urlsplit(capport.uri(url, legacy_http=True))
    origin(url)  # Also rejects protected non-web ports.
    path = parts.path or '/'
    if parts.query: path += '?' + parts.query
    return ('GET ' + path + ' HTTP/1.1\r\nHost: ' + parts.netloc
            + '\r\nAccept: text/html\r\nAccept-Encoding: identity'
            + '\r\nConnection: close\r\n\r\n').encode('ascii')


def html(body, content_type):
    # Avoid browser sniffing and lossy charset replacement: the inspected text
    # must be precisely the document on which an approval would be based.
    match = re.fullmatch(r'text/html(?:\s*;\s*charset\s*=\s*(?:"([A-Za-z0-9_-]+)"|([A-Za-z0-9_-]+)))?\s*',
                         content_type.strip(), re.IGNORECASE)
    if not match: raise ValueError('Unsupported portal HTML media type')
    charset = (match[1] or match[2] or 'utf-8').lower()
    encodings = {'utf-8': 'utf-8-sig', 'utf8': 'utf-8-sig', 'us-ascii': 'ascii',
                 'iso-8859-1': 'latin-1', 'windows-1252': 'cp1252'}
    if charset not in encodings: raise ValueError('Unsupported portal HTML charset')
    text = body.decode(encodings[charset], errors='strict')
    if not text or '\x00' in text or len(text.encode('utf-8')) > MAX_BODY:
        raise ValueError('Invalid portal HTML body')
    # Conflicting in-document encoding declarations require browser review.
    # This conservative check also covers legacy http-equiv content-type tags.
    declarations = re.findall(r'<meta\b[^>]*\bcharset\s*=\s*[\'\"]?([A-Za-z0-9_-]+)', text, re.IGNORECASE)
    for declared in declarations:
        if encodings.get(declared.lower()) != encodings[charset]:
            raise ValueError('Conflicting portal HTML charset')
    return text


def exchange(url, address, source, check, permit, deadline):
    parts = urlsplit(capport.uri(url, legacy_http=True))
    origin(url)
    address = str(ipaddress.IPv4Address(address))
    port = parts.port or (443 if parts.scheme == 'https' else 80)
    payload = request(url)
    context = None
    if parts.scheme == 'https':
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(remaining(deadline, check))
        bind_path(sock, source, portal_access.RADIO, portal_access.MARK)
        with permit(sock, address, port, 'tcp'):
            sock.settimeout(remaining(deadline, check))
            sock.connect((address, port))
            check()
            if context is not None:
                sock.settimeout(remaining(deadline, check))
                with context.wrap_socket(sock, server_hostname=parts.hostname) as secure:
                    secure.settimeout(remaining(deadline, check))
                    secure.sendall(payload)
                    return receive(secure, check, deadline, body_limit=MAX_BODY, wire_limit=MAX_WIRE)
            sock.settimeout(remaining(deadline, check))
            sock.sendall(payload)
            return receive(sock, check, deadline, body_limit=MAX_BODY, wire_limit=MAX_WIRE)


def fetch(url, context, additional_origins=None):
    """Fetch one selected portal within explicit origins and a live generation.

    context must be the worker's portal_runtime.Context, with its independent
    ownership/association/deadline checks and journalled per-socket permit. The
    worker must have separately validated selection of the initial portal URL.
    No network cache or automatic origin expansion is used.
    """
    url = capport.uri(url, legacy_http=True)
    allowed = {origin(url), *portal_origins.approved(
        [] if additional_origins is None else additional_origins, url)}
    lease = dict(context.lease)
    resolvers = list(context.resolvers)
    vehicle, transit, deadline = context.vehicle, context.transit, context.deadline
    source = str(ipaddress.IPv4Interface(lease['address']).ip)

    def check():
        context.check()
        if (context.lease != lease or context.resolvers != resolvers
                or context.vehicle != vehicle or context.transit != transit or context.deadline != deadline):
            raise RuntimeError('Portal fetch context changed')

    redirects, visited = [], set()
    for _ in range(4):
        check()
        if url in visited: raise ValueError('Portal redirect loop')
        visited.add(url)
        if origin(url) not in allowed: raise ValueError('Portal origin not approved')
        parts = urlsplit(url)
        try: addresses = [str(ipaddress.IPv4Address(parts.hostname))]
        except ValueError:
            addresses = resolve(parts.hostname, resolvers, source, portal_access.RADIO,
                                portal_access.MARK, check, context.permit, deadline)['addresses']
        check()
        if (not addresses or len(addresses) > 8 or not all(
                capport.allowed_address(address, lease, vehicle, transit) for address in addresses)):
            raise ValueError('Forbidden portal destination')
        response = None
        for address in addresses:
            check()
            try:
                response = exchange(url, address, source, check, context.permit, deadline)
                break
            except ssl.SSLError:
                # Never reinterpret an invalid certificate as an HTTP portal.
                raise
            except OSError:
                check()
        if response is None: raise ValueError('Portal HTML unavailable')
        check()
        if response['status'] in (301, 302, 303, 307, 308):
            if not response['location']: raise ValueError('Missing portal redirect')
            target = capport.uri(urljoin(url, response['location']), legacy_http=True)
            if parts.scheme == 'https' and urlsplit(target).scheme != 'https':
                raise ValueError('Portal TLS downgrade rejected')
            if origin(target) not in allowed: raise ValueError('Portal redirect origin not approved')
            redirects.append(target)
            url = target
            continue
        if response['status'] != 200: raise ValueError('Portal HTML request rejected')
        text = html(response['body'], response['content_type'])
        check()
        return {'url': url, 'redirects': redirects, 'html': text}
    raise ValueError('Too many portal redirects')
