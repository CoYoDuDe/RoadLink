#!/usr/bin/env python3
"""Guarded IPv4 VPN runtime; native management routes remain unchanged."""
import fcntl
import ipaddress
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from ap_runtime import command, token, alive
from storage import atomic_write, load_json, write_json
from vpn_config import read
from wireguard import KEY, ensure_public_key
import vpn_transport
from wan_bridge import MARK
from wan_health import probe as https_probe
from policy import Selector, Link, MODES
from dns_health import choose as choose_dns
from transport_config import read as transport_settings

ROOT = Path('/run/roadlink-vpn')
INTERFACE = 'wgroadlink'
ALIAS = 'roadlink-vpn-owned'
TAG = 'roadlink-vpn-owned'
TABLE = '51890'
PRIORITY = '21890'


def rules(config):
    # Bound-source probes must never fall back to the native management route.
    yield ['iptables', 'OUTPUT', '-s', config['address'], '!', '-o', INTERFACE,
           '-m', 'comment', '--comment', TAG, '-j', 'DROP']
    for tool in ('iptables', 'ip6tables'):
        for chain, direction in (('INPUT', '-i'), ('OUTPUT', '-o'), ('FORWARD', '-i'), ('FORWARD', '-o')):
            exception = (['!', '-o' if direction == '-i' else '-i', 'aproadlink']
                         if tool == 'iptables' and chain == 'FORWARD' else [])
            # AP owns its ingress drops, source policy and constrained permits.
            # These exclusions keep those permits valid after a VPN restart.
            yield [tool, chain, direction, INTERFACE, *exception,
                   '-m', 'comment', '--comment', TAG, '-j', 'DROP']
    yield ['iptables', 'OUTPUT', '-o', INTERFACE, '-s', config['address'],
           '-m', 'comment', '--comment', TAG, '-j', 'ACCEPT']
    yield ['iptables', 'INPUT', '-i', INTERFACE, '-d', config['address'],
           '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED',
           '-m', 'comment', '--comment', TAG, '-j', 'ACCEPT']


def cleanup():
    state = load_json(ROOT / 'state.json', {})
    errors = []
    if state:
        device = Path('/sys/class/net') / INTERFACE
        if device.exists():
            if (device / 'ifalias').read_text().strip() != ALIAS:
                errors.append('Foreign interface ownership; firewall retained')
            else:
                command(['ip', 'link', 'del', INTERFACE], check=False)
                if device.exists():
                    errors.append('VPN interface removal failed; firewall retained')
        if not errors:
            errors.extend(vpn_transport.cleanup(ROOT, command))
            command(['ip', 'rule', 'del', 'priority', PRIORITY, 'from', state['config']['address'],
                     'lookup', TABLE], check=False)
            command(['ip', 'route', 'del', 'unreachable', 'default', 'metric', '32767',
                     'table', TABLE], check=False)
            for rule in reversed(list(rules(state['config']))):
                command([rule[0], '-w', '3', '-D', *rule[1:]], check=False)
                if command([rule[0], '-w', '3', '-C', *rule[1:]], check=False).returncode == 0:
                    errors.append('VPN firewall cleanup incomplete')
            if command(['ip', 'rule', 'show']).stdout.find('lookup ' + TABLE) >= 0:
                errors.append('VPN policy cleanup incomplete')
            if command(['ip', 'route', 'show', 'table', TABLE], check=False).stdout.strip():
                errors.append('VPN routing cleanup incomplete')
    write_json(ROOT / 'result.json', {'cleaned': not errors, 'errors': errors})
    write_json(ROOT / 'status.json', {'state': 'OFF' if not errors else 'CLEANUP_FAILED',
                                    'dns_ready': False, 'internet': False})


def guard(pid, start, lock_fd):
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    write_json(ROOT / 'guard.json', {'pid': os.getpid(), 'start': token(os.getpid())})
    last, changed = None, time.monotonic()
    while alive({'pid': pid, 'start': start}) and not (ROOT / 'stop').exists():
        heartbeat = (ROOT / 'heartbeat').read_text() if (ROOT / 'heartbeat').exists() else ''
        if heartbeat != last:
            last, changed = heartbeat, time.monotonic()
        if time.monotonic() - changed > 20:
            break
        time.sleep(1)
    # Stop the mutating controller before undoing its network operations.
    if alive({'pid': pid, 'start': start}):
        try:
            os.kill(pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
    try:
        cleanup()
    finally:
        os.close(lock_fd)


def stop():
    if not ROOT.exists():
        return
    (ROOT / 'stop').touch()
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if (load_json(ROOT / 'result.json', {}).get('cleaned')
                and not alive(load_json(ROOT / 'guard.json', {}))):
            return
        time.sleep(0.2)
    raise RuntimeError('VPN cleanup incomplete; refusing package changes')


def serve(parent_pid, parent_start):
    if os.geteuid() != 0:
        raise PermissionError('Root required')
    if not transport_settings()['vpn_required']:
        raise RuntimeError('VPN transport is not selected')
    if alive(load_json(Path('/run/roadlink-direct/guard.json'), {})):
        raise RuntimeError('Direct cleanup must finish before VPN startup')
    config = read()
    if not config or not config['enabled']:
        raise ValueError('VPN not configured/enabled')
    ensure_public_key()
    lock = open('/run/roadlink-vpn.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if Path('/sys/class/net/' + INTERFACE).exists():
        raise RuntimeError('VPN interface already exists; refusing ownership')
    if ROOT.exists():
        if not load_json(ROOT / 'result.json', {}).get('cleaned'):
            raise RuntimeError('Previous VPN cleanup is incomplete')
        for item in ROOT.iterdir():
            if item.is_file() and not item.is_symlink():
                item.unlink()
            else:
                raise RuntimeError('Unexpected VPN runtime entry')
    else:
        ROOT.mkdir(mode=0o700)
    existing_rules = command(['ip', 'rule', 'show']).stdout
    existing_routes = command(['ip', 'route', 'show', 'table', TABLE], check=False).stdout
    if PRIORITY + ':' in existing_rules or existing_routes.strip():
        write_json(ROOT / 'result.json', {'cleaned': True, 'errors': []})
        raise RuntimeError('VPN routing table or priority already in use')
    write_json(ROOT / 'state.json', {'config': config})
    write_json(ROOT / 'controller.json', {'pid': os.getpid(), 'start': token(os.getpid())})
    write_json(ROOT / 'status.json', {'state': 'STARTING', 'dns_ready': False, 'internet': False})
    atomic_write(ROOT / 'heartbeat', str(time.monotonic()).encode())
    subprocess.Popen([sys.executable, __file__, 'guard', str(os.getpid()), token(os.getpid()),
                      str(lock.fileno())], pass_fds=(lock.fileno(),), start_new_session=True,
                     stdin=subprocess.DEVNULL)
    for _ in range(30):
        if alive(load_json(ROOT / 'guard.json', {})):
            break
        time.sleep(0.1)
    else:
        cleanup()
        raise RuntimeError('VPN guard unavailable; network unchanged')
    signal.signal(signal.SIGTERM, lambda *_: (ROOT / 'stop').touch())
    for rule in rules(config):
        command([rule[0], '-w', '3', '-I', rule[1], '1', *rule[2:]])
    command(['ip', 'route', 'add', 'unreachable', 'default', 'metric', '32767', 'table', TABLE])
    command(['ip', 'rule', 'add', 'priority', PRIORITY, 'from', config['address'], 'lookup', TABLE])
    vpn_transport.start(ROOT, config, command)
    command(['ip', 'link', 'add', INTERFACE, 'type', 'wireguard'])
    command(['ip', 'link', 'set', INTERFACE, 'alias', ALIAS])
    Path('/proc/sys/net/ipv6/conf/' + INTERFACE + '/disable_ipv6').write_text('1\n')
    command(['wg', 'set', INTERFACE, 'private-key', str(KEY), 'peer', config['public_key'],
             'allowed-ips', '0.0.0.0/0', 'endpoint', config['endpoint'] + ':' + str(config['port']),
             'persistent-keepalive', '15'])
    command(['wg', 'set', INTERFACE, 'fwmark', MARK])
    command(['ip', 'addr', 'add', config['address'], 'dev', INTERFACE])
    command(['ip', 'link', 'set', INTERFACE, 'mtu', str(config['mtu']), 'up'])
    command(['ip', 'route', 'add', 'default', 'dev', INTERFACE, 'metric', '10', 'table', TABLE])
    last_probe, dns_ready = float('-inf'), False
    active_dns = None
    selection = Selector(recoveries=1, failures=2)
    active, selected_route = None, None
    penalties = {'ethernet': 0, 'wifi': 0}
    wifi_penalty_profile = ''
    dns_failures = 0
    health = {}
    tunnel_https = False
    mode = 'AUTO'
    while not (ROOT / 'stop').exists():
        if not alive({'pid': parent_pid, 'start': parent_start}):
            (ROOT / 'stop').touch()
            break
        atomic_write(ROOT / 'heartbeat', str(time.monotonic()).encode())
        if time.monotonic() - last_probe >= 10:
            import dbus
            try:
                mode = str(dbus.SystemBus().get_object('com.victronenergy.settings',
                    '/Settings/RoadLink/Wan/Mode').GetValue(dbus_interface='com.victronenergy.BusItem'))
            except dbus.DBusException:
                mode = 'AUTO'
            eth = vpn_transport.ethernet(config, command)
            wan = load_json(Path('/run/roadlink-wan/status.json'), {})
            wifi = vpn_transport.wifi(wan)
            health['ethernet'] = https_probe(eth['dev']) if eth else {'healthy': False, 'score': 0}
            atomic_write(ROOT / 'heartbeat', str(time.monotonic()).encode())
            health['wifi'] = {'healthy': False, 'score': 0}
            if wifi and alive(load_json(Path('/run/roadlink-wan/guard.json'), {})):
                result = command(['ip', 'netns', 'exec', 'roadlink-wan', sys.executable,
                                  str(Path(__file__).with_name('wan_health.py')), 'disabledrlwan'], check=False)
                try:
                    import json
                    health['wifi'] = json.loads(result.stdout)
                except (ValueError, TypeError): pass
            atomic_write(ROOT / 'heartbeat', str(time.monotonic()).encode())
            now = time.monotonic()
            links = {key: Link('ONLINE' if info['healthy'] and now >= penalties[key] else 'FAILED',
                              info['score'], trusted=True) for key, info in health.items()}
            desired = selection.choose(mode, links['ethernet'], links['wifi'], now) if mode in MODES else None
            route = {'ethernet': eth, 'wifi': wifi}.get(desired)
            if route != selected_route or desired != active:
                vpn_transport.select(config, route, command)
                # Recreate the peer to discard its cached local source address
                # when switching uplinks. Its private key/interface stay put.
                command(['wg', 'set', INTERFACE, 'peer', config['public_key'], 'remove'])
                command(['wg', 'set', INTERFACE, 'peer', config['public_key'], 'allowed-ips', '0.0.0.0/0',
                         'endpoint', config['endpoint'] + ':' + str(config['port']), 'persistent-keepalive', '15'])
                active, selected_route, dns_ready, dns_failures = desired, route, False, 0
            active_dns = choose_dns(config)
            dns_ready, last_probe = bool(active_dns), time.monotonic()
            atomic_write(ROOT / 'heartbeat', str(time.monotonic()).encode())
            tunnel_https = https_probe(INTERFACE, str(ipaddress.IPv4Interface(config['address']).ip))['healthy'] if dns_ready else False
            dns_failures = 0 if dns_ready else dns_failures + 1
            if active and dns_failures >= 2:
                penalties[active] = time.monotonic() + 60
                if active == 'wifi': wifi_penalty_profile = wan.get('profile_id', '')
        values = command(['wg', 'show', INTERFACE, 'latest-handshakes']).stdout.split()
        handshake = int(values[1]) if len(values) == 2 else 0
        fresh = bool(handshake and 0 <= time.time() - handshake < 180)
        # A probe of an earlier association must never approve a reconnected
        # profile, another BSSID, namespace generation or DHCP address. The
        # next selection cycle recreates the peer and probes the new route.
        route_current = active != 'wifi' or selected_route == vpn_transport.wifi(
            load_json(Path('/run/roadlink-wan/status.json'), {}))
        ready = bool(fresh and dns_ready and tunnel_https and route_current)
        write_json(ROOT / 'status.json', {'state': 'READY' if ready else 'CONNECTING',
                   'dns_ready': bool(fresh and dns_ready and route_current), 'internet': ready,
                   'handshake': handshake, 'endpoint': config['endpoint'],
                   'address': config['address'], 'dns': active_dns or '', 'wan': active or '', 'health': health,
                   'mode': mode, 'wifi_profile_id': (selected_route or {}).get('profile_id', '') if active == 'wifi' else '',
                   'wifi_connection': (selected_route or {}).get('connection') if active == 'wifi' else None,
                   'wifi_lease': (selected_route or {}).get('lease') if active == 'wifi' else None,
                   'owner': {'pid':os.getpid(),'start':token(os.getpid())},
                   'guard':load_json(ROOT/'guard.json',{}),
                   'wifi_penalty_profile': wifi_penalty_profile,
                   'checked_at': last_probe,
                   'penalties': {key: time.monotonic() < expiry for key, expiry in penalties.items()}})
        time.sleep(1)
    # The independent guard owns final cleanup and keeps the flock until done.


if __name__ == '__main__':
    if sys.argv[1] == 'guard':
        guard(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
    elif sys.argv[1] == 'serve':
        serve(int(sys.argv[2]), sys.argv[3])
    elif sys.argv[1] == 'stop':
        stop()
    else:
        raise ValueError('Unknown VPN command')
