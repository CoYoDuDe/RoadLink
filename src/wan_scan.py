"""Passive scan parsing and a nonblocking, guard-owned scan process."""
import hashlib
import re
import time
from pathlib import Path
from storage import load_json, write_json


def decode_ssid(value):
    raw = bytearray()
    while value:
        if re.match(r'^\\x[0-9a-fA-F]{2}', value):
            raw.append(int(value[2:4], 16)); value = value[4:]
        else:
            raw.extend(value[0].encode('utf-8')); value = value[1:]
    result = raw.decode('utf-8')
    if not 1 <= len(raw) <= 32 or any(ord(c) < 32 or ord(c) == 127 for c in result):
        raise ValueError('Hidden or unsupported SSID')
    return result


def parse(output, exclude_bssids=()):
    if len(output.encode('utf-8')) > 1024 * 1024: raise ValueError('Scan output too large')
    found = {}
    for block in re.split(r'(?m)^BSS ', output)[1:]:
        if block[:17].lower() in exclude_bssids: continue
        match = re.search(r'(?m)^\s*SSID: (.*)$', block)
        signal = re.search(r'(?m)^\s*signal: (-?[0-9.]+) dBm', block)
        freq = re.search(r'(?m)^\s*freq: ([0-9.]+)', block)
        if not match or not signal or not freq: continue
        try:
            ssid = decode_ssid(match[1])
            strength, frequency = round(float(signal[1])), round(float(freq[1]))
            if not -120 <= strength <= 0 or not 2000 <= frequency <= 7200: continue
        except (ValueError, UnicodeError): continue
        privacy = bool(re.search(r'(?m)^\s*capability: .*\bPrivacy\b', block))
        rsn = re.search(r'(?m)^\tRSN:[^\n]*(?:\n\t[ \t]+[^\n]*)*', block)
        section = rsn[0] if rsn else ''
        psk = bool(re.search(r'Authentication suites:.*\bPSK\b', section))
        ccmp = bool(re.search(r'Pairwise ciphers:.*\bCCMP\b', section))
        legacy_wpa = bool(re.search(r'(?m)^\tWPA:', block))
        security = 'psk' if rsn and psk and ccmp else 'unsupported' if privacy or rsn or legacy_wpa else 'open'
        identifier = hashlib.sha256((security + '\0' + ssid).encode()).hexdigest()[:24]
        value = {'id': identifier, 'ssid': ssid, 'security': security, 'signal': strength,
                 'frequency': frequency, 'associated': '-- associated' in block.splitlines()[0]}
        if identifier not in found or strength > found[identifier]['signal']: found[identifier] = value
    return sorted(found.values(), key=lambda v: (-v['signal'], v['ssid']))[:80]


class Scanner:
    def __init__(self, root, launch):
        self.root, self.launch = root, launch
        self.process, self.output = None, None
        self.request, self.attempts, self.retry, self.started = '', 0, 0, 0

    def publish(self, state, networks=None):
        write_json(self.root / 'scan.json', {'request': self.request, 'state': state,
                   'timestamp': time.time(), 'networks': networks or []})

    def close(self):
        if self.output: self.output.close(); self.output = None
        (self.root / 'scan-output').unlink(missing_ok=True)

    def pending(self):
        request = load_json(self.root / 'scan-request.json', {}).get('request', '')
        if not re.fullmatch(r'[0-9a-f]{24}', request): return False
        current = load_json(self.root / 'scan.json', {})
        return current.get('request') != request or current.get('state') not in ('COMPLETE', 'FAILED')

    def tick(self, available):
        request = load_json(self.root / 'scan-request.json', {}).get('request', '')
        if not re.fullmatch(r'[0-9a-f]{24}', request): return
        now = time.monotonic()
        if self.process:
            result = self.process.poll()
            if result is None and now - self.started < 40: return
            if result is None:
                self.process.kill(); self.process.wait(timeout=3)
                result = -1
            self.output.close(); self.output = None
            output = (self.root / 'scan-output').read_text(encoding='utf-8', errors='replace')
            self.process = None
            self.close()
            if result == 0:
                own_ap = Path('/sys/class/net/aproadlink/address')
                excluded = [own_ap.read_text().strip().lower()] if own_ap.exists() else []
                try: self.publish('COMPLETE', parse(output, excluded))
                except ValueError: self.publish('FAILED')
                return
            if self.attempts < 3:
                self.retry = now + 3
                self.publish('WAITING')
            else:
                self.retry = float('inf'); self.publish('FAILED'); return
        if request != self.request:
            self.request, self.attempts, self.retry = request, 0, 0
            self.publish('WAITING')
        current = load_json(self.root / 'scan.json', {})
        if current.get('state') in ('COMPLETE', 'FAILED') or now < self.retry: return
        if not available: return
        self.attempts += 1
        self.output = (self.root / 'scan-output').open('wb')
        import os
        os.fchmod(self.output.fileno(), 0o600)
        self.process = self.launch('scanner', ['iw', 'dev', 'disabledrlwan', 'scan', 'passive'], stdout=self.output,
                                   stderr=self.output)
        self.started = now
        self.publish('SCANNING')
