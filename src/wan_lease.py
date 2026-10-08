"""DHCP ownership and private portal hints, without granting network access."""
import ipaddress
import re
from capport import api_hint


def connection(identifier, profile_id, bssid, state):
    if (not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{24}', identifier)
            or not isinstance(profile_id, str) or not profile_id or len(profile_id) > 128
            or not isinstance(bssid, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}', bssid)):
        raise ValueError('Invalid WLAN connection identity')
    values = {key: state.get(key) for key in ('namespace_inode', 'namespace_device', 'ifindex')}
    if any(type(value) is not int or value <= 0 for value in values.values()):
        raise ValueError('Missing namespace/radio identity')
    return dict(values, connection_id=identifier, profile_id=profile_id, bssid=bssid.lower())


def owned(current, dhcp, controller, guard, state, is_alive, parent=None):
    """Require a complete binding; PID equality without a start token is insufficient."""
    if not isinstance(current, dict) or not isinstance(dhcp, dict): return False
    try:
        expected = connection(current.get('connection_id'), current.get('profile_id'), current.get('bssid'), state)
        if current != expected or dhcp.get('connection') != current: return False
        if dhcp.get('controller') != controller or dhcp.get('guard') != guard: return False
        if parent is not None and dhcp.get('pid') != parent: return False
        return all(is_alive(item) for item in (dhcp, controller, guard))
    except (ValueError, KeyError, TypeError):
        return False


def hints(environ):
    """BusyBox 1.36.1 opt114 is hex; foreign DNS stays private portal metadata."""
    result = {'api': '', 'dns': [], 'invalid_api': False}
    raw = environ.get('opt114', '')
    if raw:
        try:
            if not isinstance(raw, str) or not re.fullmatch(r'(?:[0-9a-fA-F]{2}){1,255}', raw):
                raise ValueError('Invalid option114 encoding')
            result['api'] = api_hint(bytes.fromhex(raw).decode('ascii'))
        except (ValueError, UnicodeError):
            result['invalid_api'] = True
    offered = environ.get('dns', '')
    if isinstance(offered, str) and len(offered) <= 255:
        for value in offered.split()[:16]:
            try:
                address = ipaddress.IPv4Address(value)
                if address.is_unspecified or address.is_multicast or address.is_loopback or address.is_link_local:
                    continue
                if str(address) not in result['dns']: result['dns'].append(str(address))
            except ValueError:
                continue
    return result


def current(value, binding):
    """Lease/portal metadata may be consumed only for this exact association."""
    return bool(binding and value.get('state') == 'LEASED' and value.get('connection') == binding)
