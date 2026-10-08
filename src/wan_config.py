"""Private station configuration and minimal, non-identifying DHCP options."""
import hashlib
import re
from privacy import validate_mac


def station(profile, control):
    ssid = profile['ssid']
    if not isinstance(ssid, str) or not 1 <= len(ssid.encode()) <= 32 or '\0' in ssid:
        raise ValueError('Invalid external SSID')
    mac = validate_mac(profile['mac'])
    if not int(mac[:2], 16) & 2:
        raise ValueError('External WLAN requires a private MAC')
    if not re.fullmatch(r'/run/roadlink-wan/control', str(control)):
        raise ValueError('Unexpected station control path')
    security = profile['security']
    if security == 'psk':
        password = profile['password']
        if not isinstance(password, str) or not 8 <= len(password) <= 63 or any(
                ord(c) < 32 or ord(c) > 126 for c in password):
            raise ValueError('Invalid WPA passphrase')
        psk = hashlib.pbkdf2_hmac('sha1', password.encode('ascii'), ssid.encode(), 4096, 32).hex()
        network = 'key_mgmt=WPA-PSK\nproto=RSN\npairwise=CCMP\ngroup=CCMP\npsk={}\n'.format(psk)
    elif security == 'open':
        network = 'key_mgmt=NONE\n'
    else:
        raise ValueError('Unsupported external WLAN security')
    # Set the actual private MAC while down before starting this configuration.
    # No directed hidden-SSID probes, WPS enrollment, P2P or config mutation.
    # Venus 3.81 builds without the P2P configuration field. No P2P or WPS
    # command is used; runtime must verify that only a managed interface exists.
    return ('ctrl_interface={}\nupdate_config=0\n'
            'mac_addr=0\npreassoc_mac_addr=0\nnetwork={{\nssid={}\nscan_ssid=0\n{}}}\n').format(
                control, ssid.encode().hex(), network)


def client_name(value):
    """Optional DHCP hostname: one ASCII DNS label, never shell/config text."""
    if not isinstance(value, str) or (value and not re.fullmatch(
            r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', value)):
        raise ValueError('Use 1-63 letters, digits or internal hyphens; empty omits the name')
    return value


def dhcp_args(interface, hook, hostname=''):
    if interface != 'disabledrlwan' or str(hook) != '/data/RoadLink/src/wan_dhcp.py':
        raise ValueError('DHCP is restricted to the isolated USB station')
    # -C omits client ID, empty -V omits vendor class, -o replaces the default
    # parameter list. Only an explicitly chosen hostname is supplied.
    hostname = client_name(hostname)
    return ['udhcpc', '-f', '-B', '-n', '-t', '3', '-T', '3', '-o', '-C', '-V', '',
            '-O', '1', '-O', '3', '-O', '6', '-O', '51', '-O', '54', '-O', '114'] + (
            ['-x', 'hostname:' + hostname] if hostname else []) + ['-i', interface, '-s', str(hook)]
def wan_mode():
    import dbus
    try:
        item = dbus.SystemBus().get_object('com.victronenergy.settings', '/Settings/RoadLink/Wan/Mode')
        return str(dbus.Interface(item, 'com.victronenergy.BusItem').GetValue())
    except dbus.DBusException:
        return 'AUTO'
