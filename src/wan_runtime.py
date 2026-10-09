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
import secrets
from ap_runtime import command, token, alive
from hardware import inspect_interfaces, capabilities
import radio_roles
from profiles import Profiles
from wifi_quality import Recorder
from privacy import profile_mac
from wan_scan import Scanner
from open_wifi import Candidates
from storage import atomic_write, load_json, write_json
from wan_config import station, dhcp_args, client_name
from wan_bridge import plan, rules, ipv6_rules, bootstrap_rules
from vpn_config import read as vpn_config
from transport_config import read as transport_settings, direct_dns
from dns_config import read as dns_settings
from direct_status import current as direct_current
from reserve_policy import Gate
from wan_config import wan_mode
import wan_bridge_runtime
import owned_netns
import wan_lease
import portal_state
import portal_pins
import portal_review
import vpn_status
import portal_auto
import portal_known
import portal_session_runtime
from runtime_lock import busy as runtime_locked

ROOT = Path('/run/roadlink-wan')
NS = 'roadlink-wan'
RADIO = 'disabledrlwan'
LOCK_FD = None


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
                               token(os.getpid()), str(LOCK_FD), *args], capture_output=True, text=True,
                              timeout=8, check=check, pass_fds=(LOCK_FD,))
    return command(args, check=check)


def mutate(args):
    if (ROOT / 'stop').exists() or not alive(load_json(ROOT / 'guard.json', {})):
        raise RuntimeError('WAN guard unavailable')
    pulse()
    return tracked_command(args)


def inside(args, check=True):
    return tracked_command(['ip', 'netns', 'exec', NS, *args], check=check)


def stop_children():
    import portal_session_runtime
    portal_session_runtime.stop()
    # Revoke association-bound metadata before any child can outlive a pause.
    write_json(ROOT / 'connection.json', {})
    write_json(ROOT / 'portal-hints.json', {})
    write_json(ROOT / 'portal-result.json', {})
    write_json(ROOT / 'portal-pins.json', {})
    write_json(ROOT / 'portal-resolve-request.json', {})
    write_json(ROOT / 'portal-review-request.json', {})
    write_json(ROOT / 'portal-review-result.json', {})
    write_json(ROOT / 'lease.json', {'state': 'NO_LEASE'})
    children = [load_json(ROOT / (name + '.json'), {}) for name in ('scanner', 'mutation', 'supplicant', 'dhcp', 'dhcp_hook', 'portal', 'namespace_creator', 'enrollment')]
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
    if load_json(ROOT / 'portal-rules.json', {}):
        inside([sys.executable, str(Path(__file__).with_name('portal_runtime.py')), 'cleanup'])
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


def child(name, parent_pid, parent_start, lock_fd, args):
    if name not in ('supplicant', 'dhcp', 'mutation', 'scanner', 'portal'): raise ValueError('Unknown WLAN child')
    identity = {'pid': os.getpid(), 'start': token(os.getpid())}
    if name == 'dhcp':
        identity.update(connection=load_json(ROOT / 'connection.json', {}),
                        controller=load_json(ROOT / 'controller.json', {}),
                        guard=load_json(ROOT / 'guard.json', {}))
    write_json(ROOT / (name + '.json'), identity)
    if ((ROOT / 'stop').exists() or (ROOT / 'cleaning').exists()
            or not alive({'pid': parent_pid, 'start': parent_start})
            or not alive(load_json(ROOT / 'guard.json', {}))):
        return
    os.set_inheritable(lock_fd, False)
    os.execvp(args[0], args)


def launch(name, args, **kwargs):
    return subprocess.Popen([sys.executable, __file__, 'child', name, str(os.getpid()),
                             token(os.getpid()), str(LOCK_FD), 'ip', 'netns', 'exec', NS, *args],
                             stdin=subprocess.DEVNULL, pass_fds=(LOCK_FD,), **kwargs)


def stop():
    if not ROOT.exists() and not runtime_locked(ROOT): return
    if ROOT.exists(): (ROOT / 'stop').touch()
    controller = load_json(ROOT / 'controller.json', {})
    if alive(controller): os.kill(controller['pid'], signal.SIGTERM)
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if ((load_json(ROOT / 'result.json', {}).get('cleaned') or not ROOT.exists())
                and not alive(load_json(ROOT / 'guard.json', {})) and not runtime_locked(ROOT)): return
        time.sleep(.2)
    raise RuntimeError('WAN cleanup incomplete; refusing package changes')


def serve(parent_pid, parent_start, hostname='', auto_open=False, auto_enroll=False, role_settings=None):
    global LOCK_FD
    role_settings = dict(radio_roles.DEFAULT) if role_settings is None else radio_roles.validate(role_settings)
    if radio_roles.read() != role_settings:
        raise RuntimeError('WAN radio assignment changed before startup')
    hostname = client_name(hostname)
    if os.geteuid() != 0: raise RuntimeError('Root required')
    lock = open('/run/roadlink-wan.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    LOCK_FD = lock.fileno()
    if Path('/run/netns/' + NS).exists() or Path('/sys/class/net/' + RADIO).exists():
        raise RuntimeError('WAN namespace/interface occupied')
    store = Profiles()
    if not store.path.exists(): write_json(store.path, store.data)
    profiles = sorted((p for p in store.data['profiles'].values() if p['autoconnect']),
                      key=lambda p: (-p['priority'], p['ssid']))
    for profile in profiles: station(profile, str(ROOT / 'control'))
    use_vpn = transport_settings()['vpn_required']
    vpn = vpn_config() if use_vpn else None
    uplink = vpn if use_vpn else dict(direct_dns(dns_settings()), transport='direct')
    routable = bool(not use_vpn or vpn and vpn['enabled'])
    bootstrap = bool(use_vpn and auto_enroll and vpn is None)
    associate = routable or bootstrap
    candidates = Candidates(store.data, enabled=auto_open and associate)
    if not associate: profiles = []  # scan-only: no station association/DHCP
    dev = radio_roles.resolve(inspect_interfaces(), 'wifi_wan', role_settings)
    name = dev['interface']
    cap = capabilities(name)
    if not cap.get('known') or not cap.get('managed') or not cap.get('netns'):
        raise RuntimeError('Selected WAN radio lacks managed mode or namespace support')
    if 'Connected to' in command(['iw', 'dev', name, 'link']).stdout:
        raise RuntimeError('Native USB radio connected; refusing takeover')
    link = json.loads(command(['ip', '-j', 'link', 'show', 'dev', name]).stdout)[0]
    if ROOT.exists():
        if ROOT.is_symlink() or ROOT.stat().st_uid != 0 or ROOT.stat().st_mode & 0o077:
            raise RuntimeError('Unsafe WAN runtime directory')
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
            firewall = wan_bridge_runtime.configuration(uplink, mutate)
            for family, builder in (('iptables', rules(firewall, 'wan')), ('ip6tables', ipv6_rules('wan'))):
                for table, chain, args in builder:
                    mutate(['ip', 'netns', 'exec', NS, family, '-w', '3', '-t', table, '-I', chain, '1', *args])
        elif bootstrap:
            for family, builder in (('iptables', bootstrap_rules()), ('ip6tables', ipv6_rules('wan'))):
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
        retry, next_scan = 0, 0
        profile = None
        supplicant = dhcp = None
        portal, next_portal, portal_started = None, 0, 0
        portal_wait = portal_state.Wait()
        scan_paused = False
        scan_ready = not profiles
        started = 0
        last_health, health_failures = 0, 0
        association, connection_id = None, ''
        reserve_gate = Gate(time.monotonic())
        quality = Recorder()
        latency_ms = None
        while not (ROOT / 'stop').exists():
            if not alive({'pid': parent_pid, 'start': parent_start}): break
            if transport_settings()['vpn_required'] != use_vpn or radio_roles.read() != role_settings: break
            if not alive(load_json(ROOT / 'guard.json', {})): raise RuntimeError('WAN guard exited')
            if not namespace_owned(state): raise RuntimeError('WAN namespace lost')
            pulse()
            if not any(v['ifindex'] == state['ifindex'] for v in radio_info(True)):
                raise RuntimeError('USB radio unplugged')
            path_root = Path('/run/roadlink-vpn' if use_vpn else '/run/roadlink-direct')
            reserve_allowed = reserve_gate.allow(wan_mode(), load_json(path_root / 'status.json', {}),
                all(alive(load_json(path_root / (name + '.json'), {})) for name in ('controller', 'guard')),
                time.monotonic())
            if profile and profile.get('last_resort') and not reserve_allowed:
                stop_children(); supplicant = dhcp = None
                inside(['ip', 'link', 'set', RADIO, 'down'])
                inside(['ip', '-4', 'addr', 'flush', 'dev', RADIO])
                inside(['ip', '-4', 'route', 'flush', 'default'], check=False)
                write_json(ROOT / 'lease.json', {'state': 'NO_LEASE'})
                profile, association, connection_id, retry = None, None, '', 0
                scan_ready = False
            if profile is None and associate:
                profile = candidates.select(load_json(ROOT / 'scan.json', {}), time.time(), time.monotonic(),
                                            allow_last_resort=reserve_allowed)
            if profile is None:
                association, connection_id = None, ''
                if not scan_ready:
                    inside(['ip', 'link', 'set', RADIO, 'down'])
                    inside(['ip', '-4', 'addr', 'flush', 'dev', RADIO])
                    inside(['ip', '-4', 'route', 'flush', 'default'], check=False)
                    inside(['ip', 'link', 'set', RADIO, 'address', profile_mac(bytes.fromhex(store.data['seed']), 'passive-scan')])
                    inside(['ip', 'link', 'set', RADIO, 'up'])
                    write_json(ROOT / 'lease.json', {'state': 'NO_LEASE'})
                    scan_ready = True
                if candidates.enabled and time.monotonic() >= next_scan and not scanner.pending():
                    write_json(ROOT / 'scan-request.json', {'request': secrets.token_hex(12)})
                    next_scan = time.monotonic() + 150
                write_json(ROOT / 'status.json', {'state': 'SCAN_ONLY', 'ssid': '', 'internet': False,
                           'reserve_deferred': not reserve_allowed,
                           'driver': state['driver'], 'interface': RADIO, 'identity': state['identity']})
                scanner.tick(True)
                time.sleep(1)
                continue
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
                    association, connection_id = None, ''
                write_json(ROOT / 'status.json', {'state': 'SCAN_ONLY', 'ssid': '', 'internet': False,
                           'driver': state['driver'], 'interface': RADIO, 'identity': state['identity'], 'bridge': bridge})
                scanner.tick(True)
                time.sleep(1)
                continue
            scan_paused = False
            if supplicant is None and time.monotonic() >= retry:
                scan_ready = False
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
                last_health, health_failures = 0, 0
                latency_ms = None
            response = inside(['wpa_cli', '-p', str(ROOT / 'control'), '-i', RADIO, 'status'], check=False)
            status = dict(line.split('=', 1) for line in response.stdout.splitlines() if '=' in line)
            connected = status.get('wpa_state') == 'COMPLETED'
            current_association = (profile['id'], status.get('bssid', '')) if connected else None
            if current_association != association:
                # Revoke old hints before terminating their DHCP hook. A roam
                # or disconnect must never inherit the preceding lease/portal.
                write_json(ROOT / 'connection.json', {})
                write_json(ROOT / 'portal-hints.json', {})
                write_json(ROOT / 'lease.json', {'state': 'NO_LEASE'})
                if dhcp is not None:
                    stop_children(); supplicant = dhcp = None
                    association, connection_id = None, ''
                    inside(['ip', '-4', 'addr', 'flush', 'dev', RADIO])
                    inside(['ip', '-4', 'route', 'flush', 'default'], check=False)
                    continue
                connection_id = secrets.token_hex(12) if connected else ''
                association = current_association
                if connected:
                    write_json(ROOT / 'connection.json', wan_lease.connection(
                        connection_id, profile['id'], status.get('bssid', ''), state))
            if connected:
                radios = inside(['iw', 'dev']).stdout
                if radios.count('Interface ') != 1 or 'type managed' not in radios:
                    raise RuntimeError('Unexpected additional radio interface')
            lease = load_json(ROOT / 'lease.json', {})
            if connected and dhcp is None:
                dhcp = launch('dhcp', dhcp_args(RADIO, '/data/RoadLink/src/wan_dhcp.py', hostname))
            binding = load_json(ROOT / 'connection.json', {})
            leased = (connected and dhcp and dhcp.poll() is None and wan_lease.current(lease, binding)
                      and wan_lease.owned(binding, load_json(ROOT / 'dhcp.json', {}),
                          load_json(ROOT / 'controller.json', {}), load_json(ROOT / 'guard.json', {}), state, alive))
            resolution_due = leased and portal_pins.pending(load_json(ROOT/'portal-resolve-request.json', {}),
                load_json(ROOT/'portal-pins.json', {}), binding, lease, load_json(ROOT/'portal-hints.json', {}),
                load_json(ROOT/'portal-result.json', {}), time.monotonic())
            review_due = leased and portal_review.pending(load_json(ROOT/'portal-review-request.json', {}),
                load_json(ROOT/'portal-review-result.json', {}), binding, lease, load_json(ROOT/'portal-hints.json', {}),
                load_json(ROOT/'portal-result.json', {}), time.monotonic())
            current_portal=portal_state.current(load_json(ROOT/'portal-result.json',{}),binding,
                lease,load_json(ROOT/'portal-hints.json',{}),time.monotonic()) if leased else None
            auto_due=(leased and current_portal and current_portal.get('state') in portal_state.CAPTIVE
                and not portal_session_runtime.busy() and portal_auto.pending(current_portal,
                    {'ssid':profile['ssid'],'bssids':[binding['bssid']],'wan_mac':profile['mac']},
                    portal_known.KnownPortals(),load_json(ROOT/'portal-auto-result.json',{}),binding,lease))
            if leased and (portal is None or portal.poll() is not None) and (time.monotonic() >= next_portal or resolution_due or review_due or auto_due):
                inside([sys.executable, str(Path(__file__).with_name('portal_runtime.py')), 'cleanup'])
                resolving = resolution_due and time.monotonic() < next_portal
                reviewing = review_due and not resolving and time.monotonic() < next_portal
                automatic = auto_due and not resolving and not reviewing and time.monotonic() < next_portal
                args = [sys.executable, str(Path(__file__).with_name('portal_runtime.py'))]
                portal = launch('portal', args+(['resolve'] if resolving else ['review'] if reviewing else ['auto'] if automatic else []))
                portal_started = time.monotonic()
                if not resolving and not reviewing and not automatic: next_portal = time.monotonic() + 30
            if leased and time.monotonic() - last_health >= 10:
                pulse()
                try:
                    check = inside([sys.executable, str(Path(__file__).with_name('wan_health.py')), RADIO], check=False)
                    health = json.loads(check.stdout)
                    healthy = check.returncode == 0 and health.get('healthy') is True
                    latency_ms = health.get('latency_ms') if healthy else None
                except (ValueError, subprocess.TimeoutExpired):
                    healthy = False
                    latency_ms = None
                pulse()
                health_failures = 0 if healthy else health_failures + 1
                last_health = time.monotonic()
            scanner.tick(bool(leased))
            portal_result = portal_state.current(load_json(ROOT / 'portal-result.json', {}), binding,
                lease, load_json(ROOT / 'portal-hints.json', {}), time.monotonic()) if leased else None
            write_json(ROOT / 'status.json', {'state': 'LEASED' if leased else 'ASSOCIATED' if connected else 'CONNECTING',
                       'ssid': profile['ssid'] if connected else '', 'profile_id': profile['id'],
                       'identity': state['identity'], 'driver': state['driver'], 'interface': RADIO,
                       'address': lease.get('address', '') if leased else '', 'internet': False,
                       'connection_id': connection_id if leased else '',
                       'connection': binding if leased else None,
                       'lease': {key: lease.get(key, '') for key in ('address', 'gateway')} if leased else None,
                       'bridge': bridge, 'bootstrap': bootstrap,
                       'portal_state': (portal_result or {}).get('state', 'CHECKING' if leased and portal and portal.poll() is None else 'UNKNOWN'),
                       'https_healthy': bool(last_health and not health_failures)})
            failed = (supplicant and supplicant.poll() is not None) or (dhcp and dhcp.poll() is not None)
            vpn_state = load_json(Path('/run/roadlink-vpn/status.json'), {})
            proven = bool(use_vpn and leased and vpn_status.current_wifi(binding,lease,alive))
            if not use_vpn and leased:
                import ipaddress
                ap_address = load_json(Path('/run/roadlink-ap/status.json'), {}).get('address')
                subnet = str(ipaddress.IPv4Network(ap_address + '/24', strict=False)) if ap_address else ''
                direct = direct_current(subnet, dns_settings(), alive)
                proven = bool(direct and direct['kind'] == 'wifi')
            if leased and profile.get('discovered') and proven:
                Profiles().remember_open(profile['ssid'])
                profile['discovered'] = False
            tunnel_failed = (use_vpn and leased and vpn_state.get('penalties', {}).get('wifi', False)
                             and vpn_state.get('wifi_penalty_profile') == profile['id'])
            captive_wait = portal_wait.allow(binding if leased else None, portal_result, time.monotonic(), proven=proven)
            first_probe = (leased and portal and portal.poll() is None
                           and time.monotonic()-portal_started < 22 and not portal_result)
            rejected = bool(failed or ((health_failures >= 2 or tunnel_failed) and not captive_wait and not first_probe)
                            or (supplicant and not leased and time.monotonic() - started > 45))
            # An isolated VPN-server penalty alone is not a WLAN-quality failure.
            quality_failed = rejected and bool(failed or health_failures >= 2 or not leased)
            if quality.consider(Profiles(), profile, started, proven,
                                bool(last_health and not health_failures), latency_ms,
                                quality_failed, time.monotonic(), time.time()):
                candidates.profiles = list(Profiles().data['profiles'].values())
            if rejected:
                stop_children(); supplicant = dhcp = None
                candidates.reject(profile['id'], time.monotonic())
                profile = None
                health_failures = 0
                retry = time.monotonic() + 5
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
    if action == 'child': child(sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5]), sys.argv[6:])
    elif action == 'guard': guard(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
    elif action == 'stop': stop()
    elif action == 'serve': serve(int(sys.argv[2]), sys.argv[3], sys.argv[4] if len(sys.argv) > 4 else '',
                                len(sys.argv) > 5 and sys.argv[5] == '1', len(sys.argv) > 6 and sys.argv[6] == '1',
                                {'vehicle_ap': sys.argv[7], 'usb_identity': sys.argv[8]} if len(sys.argv) > 8 else None)
    else: raise ValueError('Unknown WAN command')
