"""Install only missing tools from the device's official Venus feeds.

Called before RoadLink stops its services. Does not upgrade all packages,
rewrite feed URLs, remove dependencies or enable RoadLink networking.
"""
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
from urllib.parse import urlsplit

TOOLS = {'hostapd': 'hostapd', 'dnsmasq': 'dnsmasq', 'wg': 'wireguard-tools',
         'ip': 'iproute2', 'iw': 'iw', 'iptables': 'iptables',
         'ip6tables': 'iptables', 'wpa_supplicant': 'wpa-supplicant'}


def missing():
    packages = {package for tool, package in TOOLS.items() if not shutil.which(tool)}
    if not Path('/sys/module/wireguard').exists():
        modprobe = shutil.which('modprobe')
        if not modprobe:
            raise RuntimeError('Die WireGuard-Kernelprüfung benötigt modprobe.')
        result = subprocess.run([modprobe, '-n', 'wireguard'], capture_output=True,
                                timeout=10, check=False)
        if result.returncode:
            version = platform.release().split('-')[0]
            if not re.fullmatch(r'[0-9]+(?:\.[0-9]+){1,3}', version):
                raise RuntimeError('Unbekannte Kernelversion; WireGuard bitte über Venus OS bereitstellen.')
            packages.add('kernel-module-wireguard-' + version)
    return sorted(packages)


def official_feeds(directory=Path('/etc/opkg')):
    """Reject additional/insecure sources before invoking native opkg."""
    found = False
    for path in sorted(directory.glob('*.conf')):
        for line in path.read_text().splitlines():
            words = line.split('#', 1)[0].split()
            if not words or words[0] not in ('src', 'src/gz'):
                continue
            if len(words) != 3:
                raise RuntimeError('Ungültige opkg-Paketquelle; bitte die Venus-Paketquellen prüfen.')
            url = urlsplit(words[2])
            if (words[0] != 'src/gz' or url.scheme != 'https'
                    or url.netloc != 'updates.victronenergy.com'
                    or not url.path.startswith('/feeds/venus/')
                    or not re.fullmatch(r'/[A-Za-z0-9_./-]+', url.path)
                    or '..' in url.path.split('/') or url.query or url.fragment):
                raise RuntimeError('Automatische Installation benötigt ausschließlich offizielle HTTPS-Venus-Paketquellen. Fehlende Pakete bitte selbst installieren oder die Quellen korrigieren.')
            found = True
    if not found:
        raise RuntimeError('Keine offizielle Venus-Paketquelle gefunden.')


def ensure(install=False):
    packages = missing()
    if not packages:
        print('RoadLink: Benötigte Netzwerkpakete sind vorhanden.', flush=True)
        return
    if not install:
        raise RuntimeError('Fehlende Netzwerkpakete: ' + ', '.join(packages))
    if os.geteuid() != 0:
        raise RuntimeError('Die Paketinstallation benötigt Root-Rechte.')
    opkg = shutil.which('opkg')
    if not opkg:
        raise RuntimeError('opkg fehlt; diese Installation benötigt Venus OS.')
    official_feeds()
    print('RoadLink: Installiere fehlende Netzwerkpakete: ' + ', '.join(packages), flush=True)
    # opkg retains its native locking, dependency and checksum checks.
    for command in ([opkg, 'update'], [opkg, '--no-install-recommends', 'install', *packages]):
        result = subprocess.run(command, timeout=180, check=False)
        if result.returncode:
            raise RuntimeError('Paketinstallation fehlgeschlagen; Internet und Venus-Paketquellen prüfen. RoadLink wurde noch nicht umgestellt.')
    remaining = missing()
    if remaining:
        raise RuntimeError('Netzwerkpakete weiterhin unvollständig: ' + ', '.join(remaining))
    print('RoadLink: Netzwerkpakete erfolgreich geprüft.', flush=True)


if __name__ == '__main__':
    try:
        if sys.argv[1:] not in ([], ['--install']):
            raise RuntimeError('Unbekannter Aufruf.')
        ensure(install=sys.argv[1:] == ['--install'])
    except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError):
        # Feed/package errors may contain proxy credentials; do not dump them.
        message = sys.exc_info()[1]
        print('RoadLink: ' + (str(message) if isinstance(message, RuntimeError)
                             else 'Netzwerkpakete konnten nicht vollständig geprüft oder installiert werden.'), file=sys.stderr)
        sys.exit(1)
