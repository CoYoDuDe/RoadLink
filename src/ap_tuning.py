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
# 'both': both radios transmit the same SSID (USB/ALFA 2.4 GHz, internal 5 GHz).
DEFAULT = {'band': 'both', 'channel_24': 6, 'channel_5': 36, 'width': 'auto', 'country': 'DE',
           'security': 'wpa2'}
BANDS = ('2.4', '5', 'both')
SECURITY = ('wpa2', 'wpa2_wpa3', 'wpa3')
FALLBACK = {'band': '2.4', 'channel': 6, 'width': 20}
CHANNELS = {'2.4': (1, 6, 11), '5': (36, 40, 44, 48)}
# 80 MHz blocks (non-DFS UNII-1 only) and HT40 secondary direction.
VHT80 = {36: 42, 40: 42, 44: 42, 48: 42}
HT40_5 = {36: '+', 40: '-', 44: '+', 48: '-'}


def validate(value):
    if not isinstance(value, dict):
        raise ValueError('Invalid AP radio settings')
    value = dict(value)
    if 'channel' in value:  # v0.27.1 schema: one channel for the single band
        channel = value.pop('channel')
        if value.get('band') == '2.4':
            value.setdefault('channel_24', channel)
        elif value.get('band') == '5':
            value.setdefault('channel_5', channel)
    value = dict(DEFAULT, **value)
    if set(value) != set(DEFAULT):
        raise ValueError('Unknown AP radio settings')
    if value['band'] not in BANDS:
        raise ValueError('Unsupported AP band')
    for key, band in (('channel_24', '2.4'), ('channel_5', '5')):
        if type(value[key]) is not int or value[key] not in CHANNELS[band]:
            raise ValueError('Unsupported AP channel')
    if value['width'] not in ('auto', 20, 40, 80):
        raise ValueError('Unsupported AP channel width')
    if value['band'] == '2.4' and value['width'] == 80:
        raise ValueError('80 MHz requires 5 GHz')
    if value['security'] not in SECURITY:
        raise ValueError('Unsupported AP security mode')
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


def sae_ap_capable(detail):
    """WPA3-SAE as AP: firmware offload, or a mac80211 driver where hostapd runs SAE."""
    if re.search(r'\[ SAE_OFFLOAD_AP \]', detail):
        return True
    soft = detail.split('software interface modes', 1)[1].split('valid interface combinations', 1)[0] \
        if 'software interface modes' in detail else ''
    return ('Device supports SAE with AUTHENTICATE command' in detail
            and re.search(r'^\s*\* AP/VLAN\s*$', soft, re.M) is not None)


SAE_PROBE_CACHE = Path('/run/roadlink-hostapd-sae.json')
SYSTEM_HOSTAPD = '/usr/sbin/hostapd'
# Optional private build with CONFIG_SAE (stock Venus hostapd lacks it). Never in the public package.
CUSTOM_HOSTAPD = Path('/data/setupOptions/RoadLink/bin/hostapd-sae')


def hostapd_sae_supported(run=None, binary='/usr/sbin/hostapd', cache=SAE_PROBE_CACHE):
    """Does the installed hostapd accept SAE (WPA3)? Stock Venus OS builds do not.

    hostapd parses the whole configuration before touching an interface, so a
    probe with a non-existent interface reports only configuration errors.
    The result is cached per binary identity.
    """
    import os
    import subprocess
    import tempfile
    try:
        info = os.stat(binary)
    except OSError:
        return False
    identity = [info.st_size, int(info.st_mtime)]
    identity.append(str(binary))
    try:
        cached = json.loads(Path(cache).read_text()).get(str(binary), {})
        if cached.get('binary') == identity:
            return cached.get('sae') is True
    except (OSError, ValueError, AttributeError):
        pass
    run = run or subprocess.run
    with tempfile.TemporaryDirectory(prefix='rl-sae-') as directory:
        conf = Path(directory) / 'probe.conf'
        conf.write_text('interface=rlsaeprobe0\ndriver=nl80211\nssid=probe\nhw_mode=g\nchannel=6\n'
                        'wpa=2\nwpa_key_mgmt=SAE\nrsn_pairwise=CCMP\nieee80211w=2\n'
                        'sae_password=probepassword\n')
        try:
            result = run([binary, str(conf)], capture_output=True, text=True, timeout=5)
            output = (result.stdout or '') + (result.stderr or '')
        except Exception:
            return False
    supported = ('invalid key_mgmt' not in output and 'unknown configuration item' not in output
                 and 'errors found in configuration' not in output)
    try:
        try:
            entries = json.loads(Path(cache).read_text())
            entries = entries if isinstance(entries, dict) else {}
        except (OSError, ValueError):
            entries = {}
        entries[str(binary)] = {'binary': identity, 'sae': supported}
        Path(cache).write_text(json.dumps(entries))
    except OSError:
        pass
    return supported


def trusted_binary(path):
    """Root-owned regular executable, not writable by group/others, in a root-only directory."""
    import os
    import stat
    try:
        info, parent = os.lstat(path), os.lstat(os.path.dirname(str(path)))
    except OSError:
        return False
    return (stat.S_ISREG(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022
            and info.st_mode & 0o100 and parent.st_uid == 0 and not parent.st_mode & 0o022)


def select_hostapd(requested_security, probe=None, custom=CUSTOM_HOSTAPD):
    """(binary, sae_available) for the requested security mode."""
    probe = probe or hostapd_sae_supported
    if requested_security == 'wpa2':
        return SYSTEM_HOSTAPD, False
    if probe(binary=SYSTEM_HOSTAPD):
        return SYSTEM_HOSTAPD, True
    if trusted_binary(custom) and probe(binary=str(custom)):
        return str(custom), True
    return SYSTEM_HOSTAPD, False


def security(requested, detail, hostapd_sae=True):
    """Effective mode; never takes the vehicle WLAN down for an unavailable WPA3.

    Without SAE support in the radio or in the installed hostapd the AP uses
    WPA2/CCMP and the menu shows that WPA3 is not available.
    """
    if requested == 'wpa2' or (hostapd_sae and sae_ap_capable(detail)):
        return requested
    return 'wpa2'


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


def plan(detail, settings, failed_before=False, band=None, hostapd_sae=True):
    """Return (directives, summary) for one radio's `iw phy` text.

    `band` selects the band for this radio; it is required in 'both' mode,
    where each radio is planned separately. On 2.4 GHz 'auto' width is 20 MHz.
    """
    settings = validate(settings)
    band = settings['band'] if band is None else band
    if band not in CHANNELS:
        raise ValueError('A single band is required for one radio')
    requested_band = band
    width = settings['width']
    if band == '2.4' and width != 40:
        width = 20
    choice = {'band': band, 'channel': settings['channel_24' if band == '2.4' else 'channel_5'],
              'width': width}
    if failed_before and band == '5':
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
           'wmm_enabled=1',
           # Weak long-range links (e.g. apartment repeater at -85 dBm) must not be
           # kicked on missing ACKs or short idle periods; they reconnect constantly.
           'disassoc_low_ack=0', 'ap_max_inactivity=600']
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
               'country': settings['country'], 'fallback': choice['band'] != requested_band,
               'security': security(settings['security'], detail, hostapd_sae),
               'security_requested': settings['security']}
    return '\n'.join(out) + '\n', summary


def mark_pending(settings, path=PENDING, pid=None):
    """Record a risky (5 GHz or dual) attempt; it stays until that plan reached ENABLED."""
    import os
    Path(path).write_text(json.dumps({'settings': validate(settings),
                                      'pid': os.getpid() if pid is None else pid}, sort_keys=True))


def clear_pending(path=PENDING):
    try:
        Path(path).unlink()
    except FileNotFoundError:
        pass


def _attempt_running(pid, proc=Path('/proc')):
    try:
        return b'ap_runtime.py' in (proc / str(int(pid)) / 'cmdline').read_bytes()
    except (OSError, ValueError, TypeError):
        return False


def failed_before(settings, path=PENDING, ignore_running=False, proc=Path('/proc')):
    """True if an attempt with these settings never reached ENABLED.

    With ignore_running (daemon view) an attempt whose AP runtime is still
    alive is in progress, not failed.
    """
    try:
        marker = json.loads(Path(path).read_text())
        if marker.get('settings') != validate(settings):
            return False
        return not (ignore_running and _attempt_running(marker.get('pid'), proc))
    except (OSError, ValueError, AttributeError):
        return False
