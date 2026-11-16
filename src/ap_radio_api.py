"""Venus menu paths for vehicle AP band, channel, width and WPA security.

Each accepted change is validated as a whole and saved atomically to
ap-radio.json. The daemon includes the saved settings in its AP signature,
so the AP restarts once with the new radio plan.
"""
import json
import os
from pathlib import Path
import ap_tuning

WIDTH_CODES = {0: 'auto', 20: 20, 40: 40, 80: 80}


def save(value, path=ap_tuning.SETTINGS):
    value = ap_tuning.validate(value)
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refusing symlink AP radio settings')
    temporary = path.with_name(path.name + '.new')
    fd = os.open(str(temporary), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as handle:
        handle.write(json.dumps(value, sort_keys=True))
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(str(temporary), str(path))
    return value


def _number(value):
    """D-Bus/GUI may deliver numbers as int, float, dbus types or digit strings."""
    if isinstance(value, bool):
        raise ValueError('Invalid number')
    if isinstance(value, str):
        value = value.strip()
        if not value.isdigit():
            raise ValueError('Invalid number')
        return int(value)
    number = float(value)
    if not number.is_integer():
        raise ValueError('Invalid number')
    return int(number)


def change(current, key, value):
    """Return the complete new settings for one menu edit, or raise ValueError."""
    new = dict(current)
    if key in ('channel24', 'channel5', 'width'):
        value = _number(value)
    elif key in ('band', 'security'):
        value = str(value)
    if key == 'band':
        if value not in ap_tuning.BANDS:
            raise ValueError('Invalid band')
        new['band'] = value
        if value == '2.4' and new['width'] == 80:
            new['width'] = 'auto'
    elif key == 'channel24':
        new['channel_24'] = value
    elif key == 'channel5':
        new['channel_5'] = value
    elif key == 'width':
        if value not in WIDTH_CODES:
            raise ValueError('Invalid width')
        new['width'] = WIDTH_CODES[value]
    elif key == 'security':
        new['security'] = value
    else:
        raise ValueError('Unknown AP radio setting')
    return ap_tuning.validate(new)


def describe(tuning):
    """Human-readable active radio state from the AP runtime's tuning.json."""
    if isinstance(tuning, dict) and isinstance(tuning.get('radios'), list):
        return ' + '.join(describe(radio) for radio in tuning['radios'])
    if not isinstance(tuning, dict) or 'band' not in tuning:
        return ''
    security = {'wpa2': 'WPA2', 'wpa2_wpa3': 'WPA2/WPA3', 'wpa3': 'WPA3'}.get(tuning.get('security'), '?')
    text = '{} GHz Kanal {}, {} MHz, {}, {}'.format(
        tuning['band'].replace('.', ','), tuning.get('channel'), tuning.get('width'),
        tuning.get('protocol'), security)
    if tuning.get('fallback'):
        text += ' (Ausweichbetrieb)'
    if tuning.get('security_requested') not in (None, tuning.get('security')):
        text += ' (WPA3 vom Funkchip nicht unterstuetzt)'
    return text


def install(service, path=ap_tuning.SETTINGS):
    try:
        current = ap_tuning.read(path)
        status = 'Funkeinstellungen geladen'
    except (ValueError, OSError):
        current, status = dict(ap_tuning.DEFAULT), 'Funkeinstellungen ungueltig; neu waehlen'
    service.add_path('/AP/RadioEditStatus', status)
    service.add_path('/AP/Radio', '')
    service.add_path('/AP/Mode', '')
    width_code = {v: k for k, v in WIDTH_CODES.items()}

    def handler(key):
        def callback(_path, value):
            try:
                try:
                    settings = ap_tuning.read(path)
                except ValueError:
                    settings = dict(ap_tuning.DEFAULT)
                new = save(change(settings, key, value), path)
            except (ValueError, OSError, TypeError):
                service['/AP/RadioEditStatus'] = 'Nicht uebernommen: Kombination nicht erlaubt'
                return False
            service['/AP/Band'] = new['band']
            service['/AP/Channel24'], service['/AP/Channel5'] = new['channel_24'], new['channel_5']
            service['/AP/Width'], service['/AP/Security'] = width_code[new['width']], new['security']
            service['/AP/RadioEditStatus'] = 'Gespeichert; Fahrzeug-WLAN startet neu'
            return True
        return callback

    service.add_path('/AP/Band', current['band'], writeable=True, onchangecallback=handler('band'))
    service.add_path('/AP/Channel24', current['channel_24'], writeable=True, onchangecallback=handler('channel24'))
    service.add_path('/AP/Channel5', current['channel_5'], writeable=True, onchangecallback=handler('channel5'))
    service.add_path('/AP/Width', width_code[current['width']], writeable=True, onchangecallback=handler('width'))
    service.add_path('/AP/Security', current['security'], writeable=True, onchangecallback=handler('security'))


def signature(path=ap_tuning.SETTINGS):
    try:
        return json.dumps(ap_tuning.read(path), sort_keys=True)
    except (ValueError, OSError):
        return 'invalid'
