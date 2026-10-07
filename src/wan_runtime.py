#!/usr/bin/env python3
"""Guarded USB station ownership; host routes/DNS are never changed here."""
import fcntl
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from ap_runtime import command, token, alive
from hardware import inspect_interfaces, resolve_role, capabilities
from profiles import Profiles
from privacy import profile_mac
from wan_scan import Scanner
from storage import atomic_write, load_json, write_json
from wan_config import station, dhcp_args
from wan_bridge import plan, rules, ipv6_rules
from vpn_config import read as vpn_config
import wan_bridge_runtime
import owned_netns

ROOT = Path('/run/roadlink-wan')
NS = 'roadlink-wan'
RADIO = 'disabledrlwan'


def native_interfaces():
    import dbus
    bus = dbus.SystemBus()
    manager = bus.get_object('fi.w1.wpa_supplicant1', '/fi/w1/wpa_supplicant1')
    props = dbus.Interface(manager, 'org.freedesktop.DBus.Properties')
    values = []
    for path in props.Get('fi.w1.wpa_supplicant1', 'Interfaces'):
        try:
            item = dbus.Interface(bus.get_object('fi.w1.wpa_supplicant1', path), 'org.freedesktop.DBus.Properties')
            values.append((path, str(item.Get('fi.w1.wpa_supplicant1.Interface', 'Ifname'))))
        except dbus.DBusException:
            pass
    return manager, values


def pulse():
    atomic_write(ROOT / 'heartbeat', str(time.monotonic()).encode())


def tracked_command(args, check=True):
    controller = load_json(ROOT / 'controller.json', {})
    if controller.get('pid') == os.getpid() and not (ROOT / 'cleaning').exists():
        return subprocess.run([sys.executable, __file__, 'child', 'mutation', str(os.getpid()),
                               token(os.getpid()), *args], capture_output=True, text=True,
                              timeout=8, check=check)
    return command(args, check=check)


def mutate(args):
    if (ROOT / 'stop').exists() or not alive(load_json(ROOT / 'guard.json', {})):
        raise RuntimeError('WAN guard unavailable')
    pulse()
    return tracked_command(args)


def inside(args, check=True):
    return tracked_command(['ip', 'netns', 'exec', NS, *args], check=check)


def stop_children():
    children = [load_json(ROOT / (name + '.json'), {}) for name in ('scanner', 'mutation', 'supplicant', 'dhcp', 'namespace_creator')]
    for sig, seconds in ((signal.SIGTERM, 3), (signal.SIGKILL, 2)):
        for state in children:
            if alive(state):
                try: os.kill(state['pid'], sig)
                except ProcessLookupError: pass
        deadline = time.monotonic() + seconds
        while any(alive(state) for state in children) and time.monotonic() < deadline:
            time.sleep(.1)
    if any(alive(state) for state in children):
        raise RuntimeError('Owned WLAN child could not stop')
    socket = ROOT / 'control' / RADIO
    if socket.is_socket(): socket.unlink()


def namespace_owned(state):
    path = Path('/run/netns') / NS
    return (not path.is_symlink() and path.exists() and path.stat().st_ino == state.get('namespace_inode')
            and (not state.get('namespace_device') or path.stat().st_dev == state['namespace_device']))


def radio_info(namespace=False):
    args = ['ip', '-j', 'link', 'show']
    result = inside(args, check=False) if namespace else command(args, check=False)
    return json.loads(result.stdout or '[]')


def cleanup():
    (ROOT / 'cleaning').touch()
    state = load_json(ROOT / 'state.json', {})
    errors = []
    try:
        stop_children()
        (ROOT / 'scan-output').unlink(missing_ok=True)
        owned_netns.remove_placeholder(state, NS)
        wan_bridge_runtime.cleanup(ROOT, command)
        ns_path = Path('/run/netns') / NS
        if ns_path.exists():
            if not namespace_owned(state):
                raise RuntimeError('Unknown namespace ownership; retained for inspection')
            items = radio_info(True)
            own = next((v for v in items if v['ifindex'] == state['ifindex']), None)
            if own:
                if own['ifname'] != RADIO:
                    raise RuntimeError('Unexpected namespace radio name')
                inside(['ip', 'link', 'set', RADIO, 'down'])
                inside(['ip', '-4', 'addr', 'flush', 'dev', RADIO])
                inside(['iw', 'phy', state['phy'], 'set', 'netns', '1'])
        original = next((v for v in radio_info() if v['ifindex'] == state.get('ifindex')), None)
        if original:
            name = original['ifname']
            if name not in (state['interface'], RADIO):
                raise RuntimeError('Radio name changed externally; restoration refused')
            command(['ip', 'link', 'set', name, 'down'])
            command(['ip', 'link', 'set', name, 'address', state['mac']])
            if name != state['interface']:
                if Path('/sys/class/net/' + state['interface']).exists():
                    raise RuntimeError('Original radio name occupied')
                command(['ip', 'link', 'set', name, 'name', state['interface']])
            Path('/proc/sys/net/ipv6/conf/' + state['interface'] + '/disable_ipv6').write_text(state['ipv6'])
            if state['up']: command(['ip', 'link', 'set', state['interface'], 'up'])
        # Unplugged radios are absent; never adopt a replacement by its name.
        if ns_path.exists():
            command(['ip', 'netns', 'del', NS])
        (ROOT / 'station.conf').unlink(missing_ok=True)
    except Exception as exc:
        errors.append(str(exc))
    write_json(ROOT / 'result.json', {'cleaned': not errors, 'errors': errors})
    write_json(ROOT / 'status.json', {'state': 'OFF' if not errors else 'CLEANUP_FAILED',
                                    'ssid': '', 'internet': False})


def guard(pid, start, lock_fd):
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    write_json(ROOT / 'guard.json', {'pid': os.getpid(), 'start': token(os.getpid())})
    last, changed = None, time.monotonic()
    while alive({'pid': pid, 'start': start}) and not (ROOT / 'stop').exists():
        heartbeat = (ROOT / 'heartbeat').read_text() if (ROOT / 'heartbeat').exists() else ''
        if heartbeat != last: last, changed = heartbeat, time.monotonic()
        if time.monotonic() - changed > 20: break
        time.sleep(.5)
    if alive({'pid': pid, 'start': start}):
        try: os.kill(pid, signal.SIGKILL)
        except ProcessLookupError: pass
    deadline = time.monotonic() + 3
    while alive({'pid': pid, 'start': start}) and time.monotonic() < deadline: time.sleep(.05)
    if alive({'pid': pid, 'start': start}):
        write_json(ROOT / 'result.json', {'cleaned': False, 'errors': ['WAN controller could not stop']})
        write_json(ROOT / 'status.json', {'state': 'CLEANUP_FAILED', 'ssid': '', 'internet': False})
        os.close(lock_fd)
        return
    try: cleanup()
    finally: os.close(lock_fd)


def child(name, parent_pid, parent_start, args):
    if name not in ('supplicant', 'dhcp', 'mutation', 'scanner'): raise ValueError('Unknown WLAN child')
    write_json(ROOT / (name + '.json'), {'pid': os.getpid(), 'start': token(os.getpid())})
    if ((ROOT / 'stop').exists() or (ROOT / 'cleaning').exists()
            or not alive({'pid': parent_pid, 'start': parent_start})):
        return
    os.execvp(args[0], args)


def launch(name, args, **kwargs):
    return subprocess.Popen([sys.executable, __file__, 'child', name, str(os.getpid()),
                             token(os.getpid()), 'ip', 'netns', 'exec', NS, *args], stdin=subprocess.DEVNULL, **kwargs)


def stop():
    if not ROOT.exists(): return
    (ROOT / 'stop').touch()
    controller = load_json(ROOT / 'controller.json', {})
    if alive(controller): os.kill(controller['pid'], signal.SIGTERM)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if (load_json(ROOT / 'result.json', {}).get('cleaned')
                and not alive(load_json(ROOT / 'guard.json', {}))): return
        time.sleep(.2)
    raise RuntimeError('WAN cleanup incomplete; refusing package changes')


def serve(parent_pid, parent_start):
    if os.geteuid() != 0: raise RuntimeError('Root required')
    lock = open('/run/roadlink-wan.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if Path('/run/netns/' + NS).exists() or Path('/sys/class/net/' + RADIO).exists():
        raise RuntimeError('WAN namespace/interface occupied')
    store = Profiles()
    if not store.path.exists(): write_json(store.path, store.data)
    profiles = sorted((p for p in store.data['profiles'].values() if p['autoconnect']),
                      key=lambda p: (-p['priority'], p['ssid']))
    for profile in profiles: station(profile, str(ROOT / 'control'))
    vpn = vpn_config()
    routable = bool(vpn and vpn['enabled'])
    if not routable: profiles = []  # scan-only: no station association/DHCP
    dev = resolve_role(inspect_interfaces(), 'wifi_wan')
    name = dev['interface']
    cap = capabilities(name)
    if not cap.get('managed'): raise RuntimeError('USB radio lacks managed mode')
    if 'Connected to' in command(['iw', 'dev', name, 'link']).stdout:
        raise RuntimeError('Native USB radio connected; refusing takeover')
    link = json.loads(command(['ip', '-j', 'link', 'show', 'dev', name]).stdout)[0]
    if ROOT.exists():
        if not load_json(ROOT / 'result.json', {}).get('cleaned'):
            raise RuntimeError('Previous WAN cleanup incomplete')
        for item in ROOT.iterdir():
            if item.is_file() and not item.is_symlink(): item.unlink()
            elif item.name == 'control' and item.is_dir() and not item.is_symlink(): item.rmdir()
            else: raise RuntimeError('Unexpected WAN runtime entry')
    else: ROOT.mkdir(mode=0o700)
    state = dict(dev, phy=cap['phy'], ifindex=link['ifindex'], up='UP' in link['flags'],
                 ipv6=Path('/proc/sys/net/ipv6/conf/' + name + '/disable_ipv6').read_text(), namespace_inode=None)
    write_json(ROOT / 'state.json', state)
    write_json(ROOT / 'controller.json', {'pid': os.getpid(), 'start': token(os.getpid())})
    write_json(ROOT / 'status.json', {'state': 'STARTING', 'ssid': '', 'internet': False})
    pulse()
    subprocess.Popen([sys.executable, __file__, 'guard', str(os.getpid()), token(os.getpid()), str(lock.fileno())],
                     pass_fds=(lock.fileno(),), start_new_session=True, stdin=subprocess.DEVNULL)
    for _ in range(30):
        if alive(load_json(ROOT / 'guard.json', {})): break
        time.sleep(.1)
    else: raise RuntimeError('WAN guard not ready')
    signal.signal(signal.SIGTERM, lambda *_: (ROOT / 'stop').touch())
    signal.signal(signal.SIGINT, lambda *_: (ROOT / 'stop').touch())
    scanner = Scanner(ROOT, launch)
    try:
        mutate(['ip', 'link', 'set', name, 'down'])
        Path('/proc/sys/net/ipv6/conf/' + name + '/disable_ipv6').write_text('1\n')
        mutate(['ip', 'link', 'set', name, 'name', RADIO])
        for attempt in range(30):
            manager, items = native_interfaces()
            owned = [(path, value) for path, value in items if value in (name, RADIO)]
            if not owned: break
            if attempt == 10:
                import dbus
                for path, _ in owned: dbus.Interface(manager, 'fi.w1.wpa_supplicant1').RemoveInterface(path)
            pulse(); time.sleep(.1)
        if owned: raise RuntimeError('Native supplicant did not release USB')
        owned_netns.create(ROOT, state, NS, pulse)
        for option in ('all', 'default'):
            mutate(['ip', 'netns', 'exec', NS, 'sysctl', '-qw', 'net.ipv6.conf.' + option + '.disable_ipv6=1'])
        # Rules exist before the radio can transmit DHCP or IP data.
        if routable:
            firewall = wan_bridge_runtime.configuration(vpn, mutate)
            for family, builder in (('iptables', rules(firewall, 'wan')), ('ip6tables', ipv6_rules('wan'))):
                for table, chain, args in builder:
                    mutate(['ip', 'netns', 'exec', NS, family, '-w', '3', '-t', table, '-I', chain, '1', *args])
        else:
            for family in ('iptables', 'ip6tables'):
                for chain in ('INPUT', 'OUTPUT', 'FORWARD'):
                    mutate(['ip', 'netns', 'exec', NS, family, '-w', '3', '-I', chain, '1',
                            '-m', 'comment', '--comment', 'roadlink-wan-scan-owned', '-j', 'DROP'])
        mutate(['iw', 'phy', state['phy'], 'set', 'netns', 'name', NS])
        mutate(['ip', 'netns', 'exec', NS, 'sysctl', '-qw', 'net.ipv6.conf.' + RADIO + '.disable_ipv6=1'])
        bridge = wan_bridge_runtime.start(ROOT, state, firewall, mutate, inside) if routable else None
        if not profiles:
            inside(['ip', 'link', 'set', RADIO, 'address', profile_mac(bytes.fromhex(store.data['seed']), 'passive-scan')])
            inside(['ip', 'link', 'set', RADIO, 'up'])
        cursor, retry = 0, 0
        supplicant = dhcp = None
        scan_paused = False
        started = 0
        while not (ROOT / 'stop').exists():
            if not alive({'pid': parent_pid, 'start': parent_start}): break
            if not alive(load_json(ROOT / 'guard.json', {})): raise RuntimeError('WAN guard exited')
            if not namespace_owned(state): raise RuntimeError('WAN namespace lost')
            pulse()
            if not any(v['ifindex'] == state['ifindex'] for v in radio_info(True)):
                raise RuntimeError('USB radio unplugged')
            if not profiles:
                write_json(ROOT / 'status.json', {'state': 'SCAN_ONLY', 'ssid': '', 'internet': False,
                           'driver': state['driver'], 'interface': RADIO, 'identity': state['identity']})
                scanner.tick(True)
                time.sleep(1)
                continue
            profile = profiles[cursor % len(profiles)]
            if scanner.pending() and (scan_paused or load_json(ROOT / 'status.json', {}).get('state') != 'LEASED'):
                if not scan_paused:
                    stop_children(); supplicant = dhcp = None
                    inside(['ip', 'link', 'set', RADIO, 'down'])
                    inside(['ip', '-4', 'addr', 'flush', 'dev', RADIO])
                    inside(['ip', '-4', 'route', 'flush', 'default'], check=False)
                    inside(['ip', 'link', 'set', RADIO, 'address', profile['mac']])
                    inside(['ip', 'link', 'set', RADIO, 'up'])
                    write_json(ROOT / 'lease.json', {'state': 'NO_LEASE'})
                    scan_paused = True
                write_json(ROOT / 'status.json', {'state': 'SCAN_ONLY', 'ssid': '', 'internet': False,
                           'driver': state['driver'], 'interface': RADIO, 'identity': state['identity'], 'bridge': bridge})
                scanner.tick(True)
                time.sleep(1)
                continue
            scan_paused = False
            if supplicant is None and time.monotonic() >= retry:
                inside(['ip', 'link', 'set', RADIO, 'down'])
                inside(['ip', '-4', 'addr', 'flush', 'dev', RADIO])
                if inside(['ip', '-4', 'route', 'show', 'default'], check=False).stdout.strip():
                    inside(['ip', '-4', 'route', 'flush', 'default'])
                inside(['ip', 'link', 'set', RADIO, 'address', profile['mac']])
                write_json(ROOT / 'lease.json', {'state': 'NO_LEASE'})
                atomic_write(ROOT / 'station.conf', station(profile, str(ROOT / 'control')).encode())
                supplicant = launch('supplicant', ['wpa_supplicant', '-Dnl80211', '-i', RADIO,
                                    '-c', str(ROOT / 'station.conf')])
                started = time.monotonic()
            response = inside(['wpa_cli', '-p', str(ROOT / 'control'), '-i', RADIO, 'status'], check=False)
            status = dict(line.split('=', 1) for line in response.stdout.splitlines() if '=' in line)
            connected = status.get('wpa_state') == 'COMPLETED'
            if connected:
                radios = inside(['iw', 'dev']).stdout
                if radios.count('Interface ') != 1 or 'type managed' not in radios:
                    raise RuntimeError('Unexpected additional radio interface')
            lease = load_json(ROOT / 'lease.json', {})
            if connected and dhcp is None:
                dhcp = launch('dhcp', dhcp_args(RADIO, '/data/RoadLink/src/wan_dhcp.py'))
            leased = connected and dhcp and dhcp.poll() is None and lease.get('state') == 'LEASED'
            scanner.tick(bool(leased))
            write_json(ROOT / 'status.json', {'state': 'LEASED' if leased else 'ASSOCIATED' if connected else 'CONNECTING',
                       'ssid': profile['ssid'] if connected else '', 'profile_id': profile['id'],
                       'identity': state['identity'], 'driver': state['driver'], 'interface': RADIO,
                       'address': lease.get('address', '') if leased else '', 'internet': False, 'bridge': bridge})
            failed = (supplicant and supplicant.poll() is not None) or (dhcp and dhcp.poll() is not None)
            if failed or (supplicant and not leased and time.monotonic() - started > 45):
                stop_children(); supplicant = dhcp = None
                cursor += 1; retry = time.monotonic() + 5
                write_json(ROOT / 'lease.json', {'state': 'NO_LEASE'})
            time.sleep(1)
    except Exception:
        # The guard kills the mutating controller before cleanup; emit the
        # cause before requesting that cleanup so diagnostics survive SIGKILL.
        import traceback
        traceback.print_exc()
        sys.stderr.flush()
        raise
    finally:
        scanner.close()
        (ROOT / 'stop').touch()
        # The independent guard stops this mutating controller before cleanup.
        if not alive(load_json(ROOT / 'guard.json', {})): cleanup()
        else:
            while not (ROOT / 'result.json').exists(): time.sleep(.2)


if __name__ == '__main__':
    action = sys.argv[1]
    if action == 'child': child(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5:])
    elif action == 'guard': guard(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
    elif action == 'stop': stop()
    elif action == 'serve': serve(int(sys.argv[2]), sys.argv[3])
    else: raise ValueError('Unknown WAN command')
