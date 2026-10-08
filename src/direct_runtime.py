#!/usr/bin/env python3
"""Explicit direct transport with an independent cleanup guard.

Launched only after the daemon's transport handover. Native routes and VPN
profiles are never changed. Default/invalid settings cannot enable this mode.
"""
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
from transport_config import read as transport_settings, direct_dns
from dns_config import read as dns_settings
from dns_health import choose, probe as dns_probe
from wan_health import probe as https_probe
from vpn_transport import ethernet, wifi
from policy import Selector, Link
from wan_config import wan_mode
from direct_policy import Policy
import direct_router as routing
import firewall_guard
from runtime_lock import busy as runtime_locked

ROOT = Path('/run/roadlink-direct')
VPN_ROOT = Path('/run/roadlink-vpn')
AP_ROOT = Path('/run/roadlink-ap')
WAN_ROOT = Path('/run/roadlink-wan')
LOCK_FD = None


def pulse():
    atomic_write(ROOT / 'heartbeat', str(time.monotonic()).encode())


def tracked(args, check=True):
    if ((ROOT / 'cleaning').exists() or (ROOT / 'stop').exists()
            or not alive(load_json(ROOT / 'guard.json', {}))):
        raise RuntimeError('Direct controller stopping')
    pulse()
    result = subprocess.run([sys.executable, __file__, 'child', str(ROOT), str(os.getpid()),
                           token(os.getpid()), str(LOCK_FD), *args], capture_output=True, text=True,
                          timeout=8, pass_fds=(LOCK_FD,))
    if check and result.returncode:
        raise RuntimeError('Direct command failed: ' + result.stderr[-1024:])
    return result


def child(root, parent, start, lock_fd, args):
    root = Path(root)
    if root.is_symlink() or root.stat().st_uid != 0 or root.stat().st_mode & 0o077:
        raise RuntimeError('Unsafe direct runtime directory')
    write_json(root / 'mutation.json', {'pid': os.getpid(), 'start': token(os.getpid())})
    if ((root / 'cleaning').exists() or (root / 'stop').exists()
            or not alive({'pid': parent, 'start': start})
            or not alive(load_json(root / 'guard.json', {}))):
        raise RuntimeError('Direct child no longer authorized')
    os.set_inheritable(lock_fd, False)
    os.execvp(args[0], args)


def cleanup():
    (ROOT / 'cleaning').touch()
    state = load_json(ROOT / 'mutation.json', {})
    if alive(state):
        os.kill(state['pid'], signal.SIGKILL)
    deadline = time.monotonic() + 3
    while alive(state) and time.monotonic() < deadline:
        time.sleep(.1)
    errors = []
    try:
        if alive(state):
            raise RuntimeError('Direct mutation child did not stop')
        Policy(ROOT, command).cleanup()
    except Exception as exc:
        errors.append(str(exc))
    write_json(ROOT / 'status.json', {'state': 'OFF' if not errors else 'CLEANUP_FAILED',
                                     'internet': False, 'dns_ready': False})
    write_json(ROOT / 'result.json', {'cleaned': not errors, 'errors': errors})


def guard(pid, start, lock_fd):
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    write_json(ROOT / 'guard.json', {'pid': os.getpid(), 'start': token(os.getpid())})
    previous, changed = None, time.monotonic()
    while alive({'pid': pid, 'start': start}) and not (ROOT / 'stop').exists():
        heartbeat = (ROOT / 'heartbeat').read_text() if (ROOT / 'heartbeat').exists() else ''
        if heartbeat != previous:
            previous, changed = heartbeat, time.monotonic()
        if time.monotonic() - changed > 20:
            break
        time.sleep(.5)
    if alive({'pid': pid, 'start': start}):
        os.kill(pid, signal.SIGKILL)
    try:
        cleanup()
    finally:
        os.close(lock_fd)


def ap_context():
    if not all(alive(load_json(AP_ROOT / (name + '.json'), {})) for name in ('controller', 'guard')):
        return None
    state = load_json(AP_ROOT / 'status.json', {})
    if state.get('state') not in ('LAN_ONLY', 'DIRECT_INTERNET', 'STARTING') or not state.get('address'):
        return None
    result = command(['ip', '-j', '-4', 'addr', 'show', 'dev', routing.AP], check=False)
    import json
    interfaces = json.loads(result.stdout or '[]')
    if not any(address.get('local') == state['address'] and address.get('prefixlen') == 24
               for interface in interfaces for address in interface.get('addr_info', [])):
        return None
    return str(ipaddress.IPv4Network(state['address'] + '/24', strict=False))


def owners(root):
    return tuple((value.get('pid'), value.get('start')) for value in
                 (load_json(root / (name + '.json'), {}) for name in ('controller', 'guard')))


def serve(parent_pid, parent_start):
    global LOCK_FD
    firewall = firewall_guard.snapshot()
    if os.geteuid() != 0 or transport_settings()['vpn_required']:
        raise RuntimeError('Explicit direct transport choice is required')
    if (Path('/sys/class/net/wgroadlink').exists()
            or alive(load_json(VPN_ROOT / 'guard.json', {}))):
        raise RuntimeError('VPN cleanup must finish before direct startup')
    ROOT.mkdir(mode=0o700, exist_ok=True)
    if ROOT.is_symlink() or ROOT.stat().st_uid != 0 or ROOT.stat().st_mode & 0o077:
        raise RuntimeError('Unsafe direct runtime directory')
    lock = open(str(ROOT) + '.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    LOCK_FD = lock.fileno()
    if not load_json(ROOT / 'result.json', {'cleaned': True}).get('cleaned'):
        raise RuntimeError('Previous direct cleanup is incomplete')
    for file in ROOT.iterdir():
        if not file.is_file() or file.is_symlink():
            raise RuntimeError('Unexpected direct runtime entry')
        file.unlink()
    write_json(ROOT / 'controller.json', {'pid': os.getpid(), 'start': token(os.getpid())})
    write_json(ROOT / 'status.json', {'state': 'STARTING', 'internet': False, 'dns_ready': False})
    pulse()
    controller_pid, controller_start = os.getpid(), token(os.getpid())
    guard_pid = os.fork()
    if guard_pid == 0:
        try:
            guard(controller_pid, controller_start, lock.fileno())
        finally:
            os._exit(0)
    for _ in range(30):
        if alive(load_json(ROOT / 'guard.json', {})):
            break
        time.sleep(.1)
    else:
        raise RuntimeError('Direct cleanup guard unavailable')
    policy = Policy(ROOT, tracked)
    try:
        policy.start()
        selector = Selector(failures=2, recoveries=1, cooldown=30, failback=60, margin=15)
        active_config, active_context = None, None
        signal.signal(signal.SIGTERM, lambda *_: (ROOT / 'stop').touch())
        while (not (ROOT / 'stop').exists() and alive({'pid': parent_pid, 'start': parent_start})
               and not transport_settings()['vpn_required']):
            firewall_guard.require(firewall)
            if not alive(load_json(ROOT / 'guard.json', {})):
                raise RuntimeError('Direct cleanup guard lost')
            policy.verify(active_config)
            settings = direct_dns(dns_settings())
            subnet = ap_context()
            ap_owners, wan_owners = owners(AP_ROOT), owners(WAN_ROOT)
            wan = load_json(WAN_ROOT / 'status.json', {})
            eth = ethernet({'endpoint': '1.1.1.1'}, tracked)
            wireless = wifi(wan) if (wan.get('bridge') or {}).get('transport') == 'direct' else None
            if not all(alive(load_json(WAN_ROOT / (name + '.json'), {})) for name in ('controller', 'guard')):
                wireless = None
            paths, health = {}, {}
            for kind, route in (('ethernet', eth), ('wifi', wireless)):
                health[kind] = {'healthy': False, 'score': 0}
                if route is None:
                    continue
                config = routing.plan(subnet or '172.27.88.0/24', dict(route, kind=kind, firewall=firewall), settings['dns'])
                policy.route(routing.TABLE, config)
                pulse()
                dns = choose(dict(settings, address=config['source']), lambda source, resolver:
                             dns_probe(source, resolver, interface=config['dev'], mark=int(routing.MARK, 16)))
                pulse()
                check = https_probe(config['dev'], config['source'], mark=int(routing.MARK, 16)) if dns else health[kind]
                if dns and check['healthy']:
                    paths[kind] = dict(config, dns=dns)
                    health[kind] = check
            current_wan = load_json(WAN_ROOT / 'status.json', {})
            if (owners(WAN_ROOT) != wan_owners
                    or any(current_wan.get(key) != wan.get(key)
                           for key in ('state', 'profile_id', 'connection_id', 'lease', 'bridge'))):
                paths.pop('wifi', None)
                health['wifi'] = {'healthy': False, 'score': 0}
            mode = wan_mode()
            selected = selector.choose(mode, *(Link('ONLINE' if health[kind]['healthy'] else 'FAILED',
                      health[kind]['score'], trusted=True) for kind in ('ethernet', 'wifi')), time.monotonic())
            desired = paths.get(selected) if subnet and ap_context() == subnet and owners(AP_ROOT) == ap_owners else None
            context = (ap_owners, wan_owners if selected == 'wifi' else None)
            if desired != active_config or context != active_context:
                policy.block()
                firewall_guard.require(firewall)
                if desired:
                    policy.activate(desired)
                active_config, active_context = desired, context
            policy.verify(active_config)
            firewall_guard.require(firewall)
            write_json(ROOT / 'status.json', {'state': 'READY' if desired else 'CONNECTING',
                       'internet': bool(desired), 'dns_ready': bool(desired), 'dns': desired['dns'] if desired else '',
                       'generation': routing.generation(desired) if desired else '',
                       'config': desired, 'wan': selected or '', 'health': health, 'mode': mode,
                       'checked_at': time.monotonic(),
                       'ap_owners': ap_owners, 'wan_owners': wan_owners if selected == 'wifi' else None,
                       'wifi_profile_id': wan.get('profile_id', '') if selected == 'wifi' else '',
                       'wifi_connection_id': wan.get('connection_id', '') if selected == 'wifi' else '',
                       'wifi_lease': wan.get('lease') if selected == 'wifi' else None})
            pulse()
            time.sleep(2)
    except firewall_guard.Changed:
        pass  # an ordinary policy edit is a controlled handover
    finally:
        (ROOT / 'stop').touch()  # independent guard owns all final cleanup
        if not alive(load_json(ROOT / 'guard.json', {})):
            cleanup()  # retain fail-closed cleanup even if the guard itself died


def stop():
    if not ROOT.exists() and not runtime_locked(ROOT):
        return
    if ROOT.exists(): (ROOT / 'stop').touch()
    deadline = time.monotonic() + 25
    while time.monotonic() < deadline:
        if ((load_json(ROOT / 'result.json', {}).get('cleaned') or not ROOT.exists())
                and not alive(load_json(ROOT / 'guard.json', {})) and not runtime_locked(ROOT)):
            return
        time.sleep(.2)
    raise RuntimeError('Direct cleanup incomplete')


if __name__ == '__main__':
    if sys.argv[1] == 'child':
        child(sys.argv[2], int(sys.argv[3]), sys.argv[4], int(sys.argv[5]), sys.argv[6:])
    elif sys.argv[1] == 'stop':
        stop()
    elif sys.argv[1] == 'serve':
        serve(int(sys.argv[2]), sys.argv[3])
    else:
        raise ValueError('Unknown direct controller command')
