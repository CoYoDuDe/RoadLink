"""Read-only Linux network hardware discovery with stable role identities."""
from pathlib import Path
import re
import subprocess


def read(path):
    try:
        return Path(path).read_text().strip()
    except (OSError, UnicodeError):
        return ''


def command(argv):
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=8)
    except (OSError, subprocess.TimeoutExpired):
        return ''
    return result.stdout if result.returncode == 0 else ''


def inspect_interfaces(sys_class_net='/sys/class/net'):
    devices = []
    for link in sorted(Path(sys_class_net).glob('*')):
        name = link.name
        if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', name):
            continue
        device = (link / 'device').resolve()
        if not device.exists() or name == 'lo':
            continue
        driver_link = device / 'driver'
        driver = driver_link.resolve().name if driver_link.exists() else ''
        usb = next((p for p in [device, *device.parents] if (p / 'idVendor').exists()), None)
        wireless = (link / 'phy80211').exists() or (link / 'wireless').exists()
        if wireless and name.startswith('ap'):
            # Native Venus/ConnMan reserve ap* for virtual AP interfaces. They
            # must not count as another physical radio when resolving roles.
            continue
        serial = read(usb / 'serial') if usb else ''
        if serial and not serial.strip('0'):
            serial = ''  # MT7612 adapters commonly report the non-unique 000000000.
        vendor = read(usb / 'idVendor') if usb else ''
        product = read(usb / 'idProduct') if usb else ''
        # No reliance on wlan0/wlan1 enumeration order; USB serial or port path is stable.
        if usb:
            identity = 'usb:{}:{}:{}'.format(vendor, product, serial or usb.name)
        else:
            identity = 'platform:' + str(device)
        if wireless and usb:
            role = 'wifi_wan_candidate'
        elif wireless and driver == 'brcmfmac':
            role = 'vehicle_ap_candidate'
        elif not wireless:
            role = 'ethernet_candidate'
        else:
            role = 'unassigned'
        devices.append({
            'interface': name, 'identity': identity, 'driver': driver,
            'wireless': wireless, 'usb_vendor': vendor, 'usb_product': product,
            'mac': read(link / 'address'), 'operstate': read(link / 'operstate'),
            'suggested_role': role,
        })
    return devices


def capabilities(interface):
    if not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}', interface):
        raise ValueError('Invalid interface name')
    info = command(['iw', 'dev', interface, 'info'])
    match = re.search(r'^\s*wiphy (\d+)\s*$', info, re.M)
    if not match:
        return {'known': False, 'ap': False, 'managed': False}
    phy = 'phy' + match.group(1)
    detail = command(['iw', 'phy', phy, 'info'])
    return {'known': bool(detail), 'phy': phy,
            'ap': bool(re.search(r'^\s*\* AP\s*$', detail, re.M)),
            'managed': bool(re.search(r'^\s*\* managed\s*$', detail, re.M))}


def resolve_role(devices, role, configured_identity=None):
    if configured_identity:
        matches = [d for d in devices if d['identity'] == configured_identity]
    else:
        matches = [d for d in devices if d['suggested_role'] == role + '_candidate']
    if len(matches) != 1:
        raise ValueError('Role {} is absent or ambiguous; explicit hardware selection required'.format(role))
    return matches[0]
