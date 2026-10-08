"""Pure per-socket permissions inside the owned WAN namespace only."""
import ipaddress
from capport import allowed_address

MARK = 0x524e
RADIO = 'disabledrlwan'
TAG = 'roadlink-portal-owned'


def rules(source, local_port, address, remote_port, protocol, lease, resolvers, vehicle_subnet, transit_subnet):
    source = str(ipaddress.IPv4Address(source))
    destination = ipaddress.IPv4Address(address)
    leased = ipaddress.IPv4Interface(lease['address'])
    if source != str(leased.ip): raise ValueError('Portal socket source differs from lease')
    if (type(local_port) is not int or not 1 <= local_port <= 65535
            or type(remote_port) is not int or not 1 <= remote_port <= 65535
            or protocol not in ('tcp', 'udp')):
        raise ValueError('Invalid portal socket')
    protected = (destination == leased.ip or destination.is_loopback or destination.is_unspecified
                 or destination.is_link_local or destination.is_multicast or destination.is_reserved
                 or any(destination in ipaddress.IPv4Network(value) for value in (vehicle_subnet, transit_subnet)))
    if protected: raise ValueError('Protected portal destination')
    if remote_port == 53:
        if str(destination) not in resolvers or not (destination.is_global or destination in leased.network):
            raise ValueError('DNS must use an exact offered resolver on the external path')
    elif protocol != 'tcp' or not allowed_address(str(destination), lease, vehicle_subnet, transit_subnet):
        raise ValueError('Portal destination denied')
    tag = ['-m', 'comment', '--comment', TAG]
    return [
        ('OUTPUT', ['-o', RADIO, '-s', source, '-d', str(destination), '-p', protocol,
                    '--sport', str(local_port), '--dport', str(remote_port),
                    '-m', 'mark', '--mark', hex(MARK) + '/0xffffffff'] + tag + ['-j', 'ACCEPT']),
        ('INPUT', ['-i', RADIO, '-d', source, '-s', str(destination), '-p', protocol,
                   '--dport', str(local_port), '--sport', str(remote_port),
                   '-m', 'conntrack', '--ctstate', 'ESTABLISHED'] + tag + ['-j', 'ACCEPT']),
    ]
