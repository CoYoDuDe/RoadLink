"""Regulatory-aware 802.11n/ac radio plan for the vehicle AP (hotfix for v0.27).

Produces the hostapd radio directives (band, channel, width, HT/VHT
capabilities, country). Only capabilities the PHY actually reports are
advertised; channels must be AP-permitted (no disabled/no-IR/radar) after
the regulatory country is applied. A 5 GHz plan that previously failed to
reach ENABLED falls back to 2.4 GHz HT20 on the next start.
"""
import json
import re
from pathlib import Path

SETTINGS = Path('/data/setupOptions/RoadLink/ap-radio.json')
PENDING = Path('/run/roadlink-ap-radio-pending.json')
DEFAULT = {'band': '5', 'channel': 36, 'width': 'auto', 'country': 'DE'}
FALLBACK = {'band': '2.4', 'channel': 6, 'width': 20}
CHANNELS = {'2.4': (1, 6, 11), '5': (36, 40, 44, 48)}
# 80 MHz blocks (non-DFS UNII-1 only) and HT40 secondary direction.
VHT80 = {36: 42, 40: 42, 44: 42, 48: 42}
HT40_5 = {36: '+', 40: '-', 44: '+', 48: '-'}


def validate(value):
    if not isinstance(value, dict):
        raise ValueError('Invalid AP radio settings')
    value = dict(DEFAULT, **value)
    if set(value) != set(DEFAULT):
        raise ValueError('Unknown AP radio settings')
    if value['band'] not in CHANNELS or type(value['channel']) is not int \
            or value['channel'] not in CHANNELS[value['band']]:
        raise ValueError('Unsupported AP band/channel')
    if value['width'] not in ('auto', 20, 40, 80):
        raise ValueError('Unsupported AP channel width')
    if value['band'] == '2.4' and value['width'] == 80:
        raise ValueError('80 MHz requires 5 GHz')
    if not isinstance(value['country'], str) or not re.fullmatch('[A-Z]{2}', value['country']) \
            or value['country'] == '00':
        raise ValueError('Invalid regulatory country')
    return value


def read(path=SETTINGS):
    path = Path(path)
    if path.is_symlink():
        raise ValueError('Refusing symlink AP radio settings')
    try:
        return validate(json.loads(path.read_text()))
    except FileNotFoundError:
        return dict(DEFAULT)


def band_body(detail, band):
    parts = re.split(r'(?m)^\s*Band ([0-9]+):\s*\n', detail)
    for body in parts[2::2]:
        freqs = [float(f) for f in re.findall(r'\*\s+([0-9.]+) MHz \[', body)]
        if band == '2.4' and any(2400 <= f < 2500 for f in freqs):
            return body
        if band == '5' and any(4900 <= f < 5925 for f in freqs):
            return body
    return None


def permitted(body, channel):
    match = re.search(r'^\s*\*\s+[0-9.]+ MHz \[' + str(channel) + r'\](.*)$', body, re.M)
    if not match:
        return False
    flags = match.group(1).lower()
    return not any(word in flags for word in ('disabled', 'no ir', 'no-ir', 'radar', 'passive scanning'))


def caps(body):
    head = body.split('Frequencies:', 1)[0]
    has = lambda text: re.search(r'^\s*' + re.escape(text) + r'\s*$', head, re.M) is not None
    vht = re.search(r'^\s*VHT Capabilities\b', head, re.M) is not None
    vht_text = head.split('VHT Capabilities', 1)[1] if vht else ''
    vhas = lambda text: re.search(r'^\s*' + re.escape(text) + r'\s*$', vht_text, re.M) is not None
    return {'ht': has('HT20/HT40') or has('HT20'), 'ht40': has('HT20/HT40'),
            'sgi20': has('RX HT20 SGI'), 'sgi40': has('RX HT40 SGI'),
            'ldpc': has('RX LDPC'), 'tx_stbc': has('TX STBC'),
            'rx_stbc1': has('RX STBC 1-stream'), 'dsss40': has('DSSS/CCK HT40'),
            'vht': vht, 'vht_sgi80': vhas('short GI (80 MHz)'),
            'vht_ldpc': vhas('RX LDPC'), 'vht_tx_stbc': vhas('TX STBC')}


def plan(detail, settings, failed_before=False):
    """Return (directives, summary) for the selected radio's `iw phy` text."""
    settings = validate(settings)
    choice = dict(settings)
    if failed_before and settings['band'] == '5':
        choice.update(FALLBACK)
    body = band_body(detail, choice['band'])
    if body is None or not permitted(body, choice['channel']):
        choice.update(FALLBACK)
        body = band_body(detail, '2.4')
        if body is None or not permitted(body, choice['channel']):
            raise ValueError('No AP-permitted channel on this radio')
    c = caps(body)
    band, channel = choice['band'], choice['channel']
    want = choice['width']
    width = 20
    if c['ht40'] and want in ('auto', 40, 80):
        if band == '5':
            partner = channel + 4 if HT40_5[channel] == '+' else channel - 4
            width = 40 if permitted(body, partner) else 20
        elif want == 40:  # 2.4 GHz HT40 only on explicit request
            partner = channel + 4 if channel <= 7 else channel - 4
            width = 40 if permitted(body, partner) else 20
    if width == 40 and band == '5' and c['vht'] and want in ('auto', 80) \
            and all(permitted(body, ch) for ch in (36, 40, 44, 48)):
        width = 80
    out = ['country_code=' + settings['country'], 'ieee80211d=1',
           'hw_mode=' + ('a' if band == '5' else 'g'), 'channel=' + str(channel),
           'wmm_enabled=1']
    if c['ht']:
        flags = []
        if width >= 40:
            if band == '5':
                flags.append('[HT40' + HT40_5[channel] + ']')
            else:
                flags.append('[HT40+]' if channel <= 7 else '[HT40-]')
        for key, flag in (('sgi20', '[SHORT-GI-20]'), ('sgi40', '[SHORT-GI-40]'), ('ldpc', '[LDPC]'),
                          ('tx_stbc', '[TX-STBC]'), ('rx_stbc1', '[RX-STBC1]')):
            if c[key] and (key != 'sgi40' or width >= 40):
                flags.append(flag)
        if c['dsss40'] and band == '2.4' and width >= 40:
            flags.append('[DSSS_CCK-40]')
        out += ['ieee80211n=1', 'ht_capab=' + ''.join(flags)]
    vht = band == '5' and c['ht'] and c['vht']
    if vht:
        vflags = [flag for key, flag in (('vht_sgi80', '[SHORT-GI-80]'), ('vht_ldpc', '[RXLDPC]'),
                                         ('vht_tx_stbc', '[TX-STBC-2BY1]')) if c[key]]
        out += ['ieee80211ac=1', 'vht_capab=' + ''.join(vflags),
                'vht_oper_chwidth=' + ('1' if width == 80 else '0')]
        if width == 80:
            out.append('vht_oper_centr_freq_seg0_idx=' + str(VHT80[channel]))
    summary = {'band': band, 'channel': channel, 'width': width,
               'protocol': '802.11ac' if vht else '802.11n' if c['ht'] else '802.11g',
               'country': settings['country'], 'fallback': choice['band'] != settings['band']}
    return '\n'.join(out) + '\n', summary


def mark_pending(settings, path=PENDING):
    """Record a 5 GHz attempt; it stays until that plan reached ENABLED."""
    Path(path).write_text(json.dumps({'settings': validate(settings)}, sort_keys=True))


def clear_pending(path=PENDING):
    try:
        Path(path).unlink()
    except FileNotFoundError:
        pass


def failed_before(settings, path=PENDING):
    try:
        return json.loads(Path(path).read_text()).get('settings') == validate(settings)
    except (OSError, ValueError):
        return False
