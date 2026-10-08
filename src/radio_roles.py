"""Portable radio preferences, resolved by physical identity rather than name."""
from pathlib import Path
import re
from storage import load_json, write_json

CONFIG = Path('/data/setupOptions/RoadLink/radio-roles.json')
DEFAULT = {'vehicle_ap': 'internal', 'usb_identity': ''}


def validate(value):
    if not isinstance(value, dict) or set(value) != set(DEFAULT):
        raise ValueError('Invalid radio role settings')
    if value['vehicle_ap'] not in ('internal', 'usb'):
        raise ValueError('Choose the internal or USB vehicle radio')
    identity = value['usb_identity']
    if (not isinstance(identity, str) or len(identity) > 256
            or any(ord(c) < 32 or ord(c) == 127 for c in identity)
            or identity and not re.fullmatch(r'usb:[0-9a-f]{4}:[0-9a-f]{4}:.+', identity)):
        raise ValueError('Invalid USB physical identity')
    return dict(value)


def read(path=CONFIG):
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Refusing symlink radio settings')
    return validate(load_json(path, dict(DEFAULT)))


def save(value, path=CONFIG):
    value = validate(value)
    path = Path(path)
    if path.is_symlink() or path.parent.is_symlink():
        raise ValueError('Refusing symlink radio settings')
    write_json(path, value)


def generation(value):
    value = validate(value)
    return value['vehicle_ap'], value['usb_identity']


def resolve(devices, role, value):
    value = validate(value)
    if role not in ('vehicle_ap', 'wifi_wan'):
        raise ValueError('Unknown radio role')
    usb = (role == 'vehicle_ap') == (value['vehicle_ap'] == 'usb')
    category = 'wifi_wan_candidate' if usb else 'vehicle_ap_candidate'
    candidates = [device for device in devices if device.get('wireless') is True
                  and device.get('suggested_role') == category]
    if usb and value['usb_identity']:
        candidates = [device for device in candidates if device['identity'] == value['usb_identity']]
    if len(candidates) != 1:
        raise ValueError('Selected radio is absent or ambiguous')
    return candidates[0]
