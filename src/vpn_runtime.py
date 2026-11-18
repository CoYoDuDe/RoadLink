#!/usr/bin/env python3
"""Guarded IPv4 VPN runtime; native management routes remain unchanged."""
import fcntl
import logging
import select
import ipaddress
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from ap_runtime import command as raw_command, token, alive
from storage import atomic_write, load_json, write_json
from readonly_command import is_readonly
from vpn_config import read
from wireguard import KEY, ensure_public_key
import vpn_transport
from wan_bridge import MARK
from wan_health import probe as https_probe
from policy import Selector, Link, MODES
from dns_health import choose as choose_dns
from transport_config import read as transport_settings

# Tunnel DNS failures in a row (10 s apart) before the uplink is penalised.
DNS_PENALTY_FAILURES = 3

ROOT = Path('/run/roadlink-vpn')
INTERFACE = 'wgroadlink'
ALIAS = 'roadlink-vpn-owned'
TAG = 'roadlink-vpn-owned'
TABLE = '51890'
PRIORITY = '21890'
LOCK_FD = None


def authorize_command(pid, start, args):
    identity = {'pid': pid, 'start': start}
    if ((ROOT / 'stop').exists() or (ROOT / 'cleaning').exists()
            or load_json(ROOT / 'controller.json', {}) != identity
            or not alive(identity) or not alive(load_json(ROOT / 'guard.json', {}))):
        raise RuntimeError('VPN command controller is stopping or changed')
    if args[:4] == ['ip', 'netns', 'exec', 'roadlink-wan']:
        state = load_json(Path('/run/roadlink-wan/state.json'), {})
        namespace = Path('/run/netns/roadlink-wan')
        if namespace.is_symlink():
            raise RuntimeError('VPN WLAN namespace is a symlink')
        info = namespace.stat()
        if (info.st_dev, info.st_ino) != (state.get('namespace_device'), state.get('namespace_inode')):
            raise RuntimeError('VPN WLAN namespace changed')


def command(args, check=True):
    if LOCK_FD is None:
        return raw_command(args, check=check)
    start = token(os.getpid())
    authorize_command(os.getpid(), start, args)
    atomic_write(ROOT / 'heartbeat', str(time.monotonic()).encode())
    if is_readonly(args):
        return subprocess.run(list(args), capture_output=True, text=True, timeout=8, check=check)
    return subprocess.run([sys.executable, __file__, 'child', str(os.getpid()), start,
                           str(LOCK_FD), *args], capture_output=True, text=True,
                          timeout=8, check=check, pass_fds=(LOCK_FD,))


def child(pid, start, lock_fd, args):
    from cleanup_guard import CleanupGuard
    context = CleanupGuard(ROOT, pid, start, lock_fd)
    try:
        context.held()
        write_json(ROOT / 'mutation.json', context.me)
        authorize_command(pid, start, args)
        os.set_inheritable(lock_fd, False)
    finally:
        context.close()
    os.execvp(args[0], args)


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
                raw_command(['ip', 'link', 'del', INTERFACE], check=False)
                if device.exists():
                    errors.append('VPN interface removal failed; firewall retained')
        if not errors:
            errors.extend(vpn_transport.cleanup(ROOT, raw_command))
            raw_command(['ip', 'rule', 'del', 'priority', PRIORITY, 'from', state['config']['address'],
                     'lookup', TABLE], check=False)
            raw_command(['ip', 'route', 'del', 'unreachable', 'default', 'metric', '32767',
                     'table', TABLE], check=False)
            for rule in reversed(list(rules(state['config']))):
                raw_command([rule[0], '-w', '3', '-D', *rule[1:]], check=False)
                if raw_command([rule[0], '-w', '3', '-C', *rule[1:]], check=False).returncode == 0:
                    errors.append('VPN firewall cleanup incomplete')
            if raw_command(['ip', 'rule', 'show']).stdout.find('lookup ' + TABLE) >= 0:
                errors.append('VPN policy cleanup incomplete')
            if raw_command(['ip', 'route', 'show', 'table', TABLE], check=False).stdout.strip():
                errors.append('VPN routing cleanup incomplete')
    result = {'cleaned': not errors, 'errors': errors}
    write_json(ROOT / 'result.json', result)
    write_json(ROOT / 'status.json', {'state': 'OFF' if not errors else 'CLEANUP_FAILED',
                                    'dns_ready': False, 'internet': False})
    return result


def cleanup_with_retry(link):
    """Retry reaped command timeouts while the same guard retains ownership.

    subprocess.run raises TimeoutExpired only after killing/waiting for its
    command child. A child still stuck in the kernel therefore cannot overlap
    a retry. Ownership/validation failures and incomplete cleanup results are
    not treated as transient. The independent client's release remains gated
    by after_cleanup and its exact successful receipt.
    """
    attempts, first_failure = 0, None
    while True:
        link.held()
        if not select.select([link.ownerfd], [], [], 0)[0]:
            raise RuntimeError('Controller must be terminal before cleanup retry')
        try:
            result = cleanup()
        except subprocess.TimeoutExpired:
            link.held()
            attempts += 1
            if first_failure is None:
                first_failure = time.monotonic()
                logging.error('VPN cleanup command timed out; original guard retains lock and retries')
            delay = (1, 5, 15, 30)[min(attempts - 1, 3)]
            write_json(ROOT / 'cleanup-fault.json', {
                'kind': 'command_timeout', 'attempts': attempts,
                'first_checked_at': first_failure, 'checked_at': time.monotonic(),
                'retry_after': delay, 'guard': link.me, 'owner': link.owner})
            write_json(ROOT / 'result.json', {'cleaned': False,
                       'errors': ['VPN cleanup command timed out; original guard retains lock']})
            write_json(ROOT / 'status.json', {'state': 'CLEANUP_FAILED',
                       'dns_ready': False, 'internet': False, 'retrying': True})
            time.sleep(delay)
            continue
        if attempts and result == {'cleaned': True, 'errors': []}:
            logging.warning('VPN cleanup recovered after %d command timeouts', attempts)
        return result

def guard(pid, start, lock_fd):
    from cleanup_guard import CleanupGuard
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    context = CleanupGuard(ROOT, pid, start, lock_fd)
    try:
        write_json(ROOT / 'guard.json', context.me)
        try:
            last, changed = None, time.monotonic()
            while alive(context.owner) and not (ROOT / 'stop').exists():
                heartbeat = (ROOT / 'heartbeat').read_text() if (ROOT / 'heartbeat').exists() else ''
                if heartbeat != last:
                    last, changed = heartbeat, time.monotonic()
                if time.monotonic() - changed > 20:
                    break
                time.sleep(1)
        except Exception as error:
            logging.error('VPN guard observation failed: %s', type(error).__name__)
        context.held()
        (ROOT / 'cleaning').touch()
        context.stop_controller()
        context.stop_mutation(load_json(ROOT / 'mutation.json', {}))
        cleanup_with_retry(context)
        context.held()
        if load_json(ROOT / 'result.json', {}).get('cleaned') is not True:
            raise RuntimeError('VPN cleanup did not complete')
    except Exception as error:
        logging.error('VPN cleanup retained for inspection: %s', type(error).__name__)
        try:
            context.held()
            write_json(ROOT / 'result.json', {'cleaned': False,
                       'errors': ['VPN cleanup unconfirmed; original guard retains lock'],
                       'error_kind': type(error).__name__})
            write_json(ROOT / 'status.json', {'state': 'CLEANUP_FAILED',
                       'dns_ready': False, 'internet': False})
        except Exception:
            logging.error('VPN failure receipt unavailable; original lock retained')
        # No competing controller may replace an unconfirmed generation.
        while True:
            time.sleep(30)
    finally:
        context.close()
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
    global LOCK_FD
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
    # Nothing is owned yet: keep a clean receipt so an aborted start (e.g. a
    # timed-out read while the kernel network lock is blocked) never leaves an
    # empty runtime that blocks every later handover.
    write_json(ROOT / 'result.json', {'cleaned': True, 'errors': []})
    existing_rules = command(['ip', 'rule', 'show']).stdout
    existing_routes = command(['ip', 'route', 'show', 'table', TABLE], check=False).stdout
    if PRIORITY + ':' in existing_rules or existing_routes.strip():
        write_json(ROOT / 'result.json', {'cleaned': True, 'errors': []})
        raise RuntimeError('VPN routing table or priority already in use')
    (ROOT / 'result.json').unlink()  # ownership starts with the state journal
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
    LOCK_FD = lock.fileno()
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
    tunnel_failures = 0
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
                tunnel_https, tunnel_failures, active_dns = False, 0, None
            atomic_write(ROOT / 'heartbeat', str(time.monotonic()).encode())
            resolved = choose_dns(config)
            # Same hysteresis as the HTTPS probe: one missed answer keeps the
            # resolver; the penalty below still needs consecutive failures.
            dns_failures = 0 if resolved else dns_failures + 1
            active_dns = resolved or (active_dns if dns_failures < 2 else None)
            dns_ready, last_probe = bool(active_dns), time.monotonic()
            atomic_write(ROOT / 'heartbeat', str(time.monotonic()).encode())
            probed = https_probe(INTERFACE, str(ipaddress.IPv4Interface(config['address']).ip))['healthy'] if dns_ready else False
            # A single lost probe on a slow multi-hop hotspot keeps the tunnel
            # ready; two consecutive failures (about 20 s) withdraw it.
            tunnel_failures = 0 if probed else tunnel_failures + 1
            tunnel_https = probed or (tunnel_https and tunnel_failures < 2)
            if active and dns_failures >= DNS_PENALTY_FAILURES:
                penalties[active] = time.monotonic() + 60
                if active == 'wifi': wifi_penalty_profile = wan.get('profile_id', '')
        # Date the current route observation independently of slow probes.
        # Internet/DNS checked_at retains its original measurement time.
        management_checked_at = time.monotonic()
        values = command(['wg', 'show', INTERFACE, 'latest-handshakes']).stdout.split()
        handshake = int(values[1]) if len(values) == 2 else 0
        fresh = bool(handshake and values[0] == config['public_key']
                     and 0 <= time.time() - handshake < 180)
        # A probe of an earlier association must never approve a reconnected
        # profile, another BSSID, namespace generation or DHCP address. The
        # next selection cycle recreates the peer and probes the new route.
        route_current = active != 'wifi' or selected_route == vpn_transport.wifi(
            load_json(Path('/run/roadlink-wan/status.json'), {}))
        management_current = bool(active and route_current)
        if active == 'ethernet':
            management_current = selected_route == vpn_transport.ethernet(config, command)
        elif active == 'wifi':
            import wan_lease
            wan_root = Path('/run/roadlink-wan')
            binding = (selected_route or {}).get('connection')
            lease = load_json(wan_root / 'lease.json', {})
            namespace = Path('/run/netns/roadlink-wan')
            try:
                info = namespace.stat()
                namespace_current = bool(binding and not namespace.is_symlink()
                    and (info.st_dev, info.st_ino) ==
                        (binding.get('namespace_device'), binding.get('namespace_inode')))
            except OSError:
                namespace_current = False
            management_current = bool(management_current and binding
                and load_json(wan_root / 'connection.json', {}) == binding
                and wan_lease.current(lease, binding)
                and {key: lease.get(key) for key in ('address', 'gateway')} == selected_route.get('lease')
                and namespace_current
                and not any((wan_root / name).exists() for name in ('stop', 'cleaning', 'result.json'))
                and wan_lease.owned(binding, load_json(wan_root / 'dhcp.json', {}),
                    load_json(wan_root / 'controller.json', {}), load_json(wan_root / 'guard.json', {}),
                    load_json(wan_root / 'state.json', {}), alive))
        ready = bool(fresh and dns_ready and tunnel_https and route_current)
        write_json(ROOT / 'status.json', {'state': 'READY' if ready else 'CONNECTING',
                   'dns_ready': bool(fresh and dns_ready and route_current), 'internet': ready,
                   'management_checked_at': management_checked_at if fresh and management_current else None,
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
    elif sys.argv[1] == 'child':
        child(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]), sys.argv[5:])
    elif sys.argv[1] == 'serve':
        serve(int(sys.argv[2]), sys.argv[3])
    elif sys.argv[1] == 'stop':
        stop()
    else:
        raise ValueError('Unknown VPN command')
