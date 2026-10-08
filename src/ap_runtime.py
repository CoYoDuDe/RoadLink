#!/usr/bin/env python3
"""AP runtime with independent cleanup. WAN forwarding remains fail-closed."""
import fcntl
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from ap_config import hostapd, isolated_dhcp, choose_subnet
from hardware import inspect_interfaces, resolve_role
from storage import atomic_write, load_json, write_json
from vpn_config import read as vpn_config
from dns_config import routed as routed_dns, ready as dns_ready
from dns_config import read as dns_settings
from transport_config import read as transport_settings
from direct_status import current as direct_current
import ap_router

ROOT = Path('/run/roadlink-ap')
SECRET = Path('/data/setupOptions/RoadLink/ap-secret.json')
INTERFACE = 'aproadlink'
TAG = 'roadlink-ap-owned'


def command(args, check=True):
    return subprocess.run(args, capture_output=True, text=True, timeout=8, check=check)


def token(pid):
    try:
        fields = Path('/proc/{}/stat'.format(int(pid))).read_text().rsplit(')', 1)[1].split()
        return None if fields[0] == 'Z' else fields[19]
    except (OSError, ValueError, IndexError):
        return None


def alive(state):
    return bool(state and state.get('start') and token(state['pid']) == state['start'])


def rules():
    for tool in ('iptables', 'ip6tables'):
        for chain, direction in (('FORWARD', '-i'), ('FORWARD', '-o'), ('INPUT', '-i'), ('OUTPUT', '-o')):
            base = [tool, chain, direction, INTERFACE]
            tag = ['-m', 'comment', '--comment', TAG]
            yield base + tag + ['-j', 'DROP']
            if tool == 'iptables' and chain in ('INPUT', 'OUTPUT'):
                yield base + ['-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED'] + tag + ['-j', 'ACCEPT']
                if chain == 'INPUT':
                    yield base + ['-p', 'tcp', '-m', 'multiport', '--dports', '22,80,443'] + tag + ['-j', 'ACCEPT']
                yield base + ['-p', 'udp', '--sport', '68' if chain == 'INPUT' else '67',
                             '--dport', '67' if chain == 'INPUT' else '68'] + tag + ['-j', 'ACCEPT']


def cleanup():
    (ROOT / 'cleaning').touch()
    errors = []
    for name in ('hostapd', 'dnsmasq'):
        state = load_json(ROOT / (name + '.json'), {})
        if alive(state):
            try:
                os.kill(state['pid'], signal.SIGTERM)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + 3
    children = [load_json(ROOT / (name + '.json'), {}) for name in ('hostapd', 'dnsmasq')]
    while any(alive(state) for state in children) and time.monotonic() < deadline:
        time.sleep(0.1)
    for state in children:
        if alive(state):
            try:
                os.kill(state['pid'], signal.SIGKILL)
            except ProcessLookupError:
                pass
    deadline = time.monotonic() + 2
    while any(alive(state) for state in children) and time.monotonic() < deadline:
        time.sleep(0.1)
    if any(alive(state) for state in children):
        errors.append('Owned AP process did not stop')
    else:
        control_socket = ROOT / 'control' / INTERFACE
        if control_socket.is_socket():
            control_socket.unlink()
    # Remove interface before permitting traffic by removing the owned rules.
    command(['iw', 'dev', INTERFACE, 'del'], check=False)
    if Path('/sys/class/net/' + INTERFACE).exists():
        errors.append('AP interface removal failed; firewall retained')
    else:
        errors.extend(ap_router.cleanup(ROOT, command))
        for rule in reversed(list(rules())):
            command([rule[0], '-w', '3', '-D', *rule[1:]], check=False)
            if command([rule[0], '-w', '3', '-C', *rule[1:]], check=False).returncode == 0:
                errors.append('Firewall cleanup incomplete')
    (ROOT / 'hostapd.conf').unlink(missing_ok=True)
    write_json(ROOT / 'result.json', {'cleaned': not errors, 'errors': errors})


def guard(pid, start, lock_fd):
    # Retains controller's flock until cleanup ends, even if controller is killed.
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    write_json(ROOT / 'guard.json', {'pid': os.getpid(), 'start': token(os.getpid())})
    last = None
    changed = time.monotonic()
    while alive({'pid': pid, 'start': start}) and not (ROOT / 'stop').exists():
        heartbeat = (ROOT / 'heartbeat').read_text() if (ROOT / 'heartbeat').exists() else ''
        if heartbeat != last:
            last, changed = heartbeat, time.monotonic()
        if time.monotonic() - changed > 15:
            break
        time.sleep(1)
    try:
        # Prevent route/DHCP mutation racing independent cleanup.
        if alive({'pid': pid, 'start': start}):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        cleanup()
    finally:
        os.close(lock_fd)


def launch(name, args):
    # Child logs go through the parent's bounded SetupHelper multilog service.
    # The child records its own identity before exec. Killing the controller
    # between Popen and PID recording must not leave an untracked process.
    return subprocess.Popen([sys.executable, __file__, 'child', name, str(os.getpid()),
                             token(os.getpid()), *args], stdin=subprocess.DEVNULL)


def child(name, parent_pid, parent_start, args):
    if name not in ('hostapd', 'dnsmasq'):
        raise ValueError('Unknown AP child')
    write_json(ROOT / (name + '.json'), {'pid': os.getpid(), 'start': token(os.getpid())})
    if ((ROOT / 'cleaning').exists() or (ROOT / 'stop').exists()
            or not alive({'pid': parent_pid, 'start': parent_start})):
        return
    os.execvp(args[0], args)


def stop():
    if not ROOT.exists():
        return
    state = load_json(ROOT / 'controller.json', {})
    (ROOT / 'stop').touch()
    if alive(state):
        os.kill(state['pid'], signal.SIGTERM)
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        result = load_json(ROOT / 'result.json', {})
        if result.get('cleaned') and not alive(load_json(ROOT / 'guard.json', {})):
            return
        time.sleep(0.2)
    raise RuntimeError('AP cleanup is incomplete; refusing installation/uninstall')


def serve(ssid, parent_pid, parent_start):
    if os.geteuid() != 0:
        raise RuntimeError('Root required')
    lock = open('/run/roadlink-ap.lock', 'a')
    fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    if Path('/sys/class/net/' + INTERFACE).exists():
        raise RuntimeError('AP interface already exists; refusing to take ownership')
    if ROOT.exists():
        if not load_json(ROOT / 'result.json', {}).get('cleaned'):
            raise RuntimeError('Previous AP cleanup is incomplete')
        for item in ROOT.iterdir():
            if item.is_file() and not item.is_symlink():
                item.unlink()
            elif item.name == 'control' and item.is_dir() and not item.is_symlink():
                item.rmdir()  # hostapd must have removed its control socket
            else:
                raise RuntimeError('Unexpected runtime entry')
    else:
        ROOT.mkdir(mode=0o700)
    write_json(ROOT / 'result.json', {'cleaned': True, 'errors': []})
    secret = load_json(SECRET, {})
    config = hostapd(INTERFACE, ssid, secret.get('password', ''))
    dev = resolve_role(inspect_interfaces(), 'vehicle_ap')
    if 'Connected to' in command(['iw', 'dev', dev['interface'], 'link']).stdout:
        raise RuntimeError('Internal radio is in use')
    routes = json.loads(command(['ip', '-j', '-4', 'route', 'show', 'table', 'all']).stdout)
    subnet = choose_subnet([r['dst'] for r in routes if r.get('dst') not in (None, 'default')])
    address = str(ipaddress.ip_network(subnet)[1])
    use_vpn = transport_settings()['vpn_required']
    vpn = vpn_config() if use_vpn else None
    vpn_status = load_json(Path('/run/roadlink-vpn/status.json'), {})
    routing = ap_router.plan(subnet, routed_dns(vpn, vpn_status)) if vpn and vpn['enabled'] else None
    config += 'ctrl_interface=' + str(ROOT / 'control') + '\n'
    atomic_write(ROOT / 'hostapd.conf', config.encode())
    dhcp = isolated_dhcp(INTERFACE, subnet).replace('/run/roadlink/ap.leases', str(ROOT / 'leases'))
    atomic_write(ROOT / 'dnsmasq.conf', dhcp.encode())
    command(['dnsmasq', '--test', '--conf-file=' + str(ROOT / 'dnsmasq.conf')])
    write_json(ROOT / 'controller.json', {'pid': os.getpid(), 'start': token(os.getpid())})
    write_json(ROOT / 'status.json', {'state': 'STARTING', 'address': address, 'ssid': ssid, 'internet': False})
    (ROOT / 'result.json').unlink()
    subprocess.Popen([sys.executable, __file__, 'guard', str(os.getpid()), token(os.getpid()), str(lock.fileno())],
                     pass_fds=(lock.fileno(),), start_new_session=True, stdin=subprocess.DEVNULL)
    for _ in range(30):
        if alive(load_json(ROOT / 'guard.json', {})):
            break
        time.sleep(0.1)
    else:
        raise RuntimeError('Guard unavailable; network unchanged')
    signal.signal(signal.SIGTERM, lambda *_: (ROOT / 'stop').touch())
    signal.signal(signal.SIGINT, lambda *_: (ROOT / 'stop').touch())
    for rule in rules():
        command([rule[0], '-w', '3', '-I', rule[1], '1', *rule[2:]])
    command(['iw', 'dev', dev['interface'], 'interface', 'add', INTERFACE, 'type', '__ap'])
    Path('/proc/sys/net/ipv6/conf/' + INTERFACE + '/disable_ipv6').write_text('1\n')
    command(['ip', 'addr', 'add', address + '/24', 'dev', INTERFACE])
    command(['ip', 'link', 'set', INTERFACE, 'up'])
    if routing:
        ap_router.start(ROOT, routing, command)
    initial_vpn = load_json(Path('/run/roadlink-vpn/status.json'), {})
    advertised_dns = (routing['dns'] if routing and dns_ready(vpn, initial_vpn)
                      and routing['dns'] == initial_vpn.get('dns')
                      and alive(load_json(Path('/run/roadlink-vpn/controller.json'), {}))
                      and alive(load_json(Path('/run/roadlink-vpn/guard.json'), {})) else None)
    if advertised_dns:
        dhcp = isolated_dhcp(INTERFACE, subnet, advertised_dns).replace(
            '/run/roadlink/ap.leases', str(ROOT / 'leases'))
        atomic_write(ROOT / 'dnsmasq.conf', dhcp.encode())
        command(['dnsmasq', '--test', '--conf-file=' + str(ROOT / 'dnsmasq.conf')])
    ap = launch('hostapd', ['hostapd', str(ROOT / 'hostapd.conf')])
    dhcp_process = launch('dnsmasq', ['dnsmasq', '--keep-in-foreground', '--conf-file=' + str(ROOT / 'dnsmasq.conf')])
    ready = False
    startup_deadline = time.monotonic() + 20
    while not (ROOT / 'result.json').exists():
        if not alive({'pid': parent_pid, 'start': parent_start}):
            (ROOT / 'stop').touch()
        if not (ROOT / 'cleaning').exists() and (ap.poll() is not None or dhcp_process.poll() is not None):
            (ROOT / 'stop').touch()
        if not (ROOT / 'stop').exists():
            if transport_settings()['vpn_required'] != use_vpn:
                (ROOT / 'stop').touch()
                continue
            atomic_write(ROOT / 'heartbeat', str(time.monotonic()).encode())
            response = command(['hostapd_cli', '-p', str(ROOT / 'control'), '-i', INTERFACE, 'status'], check=False)
            ready = 'state=ENABLED' in response.stdout.splitlines()
            if not ready and time.monotonic() > startup_deadline:
                (ROOT / 'stop').touch()
            vpn_state = load_json(Path('/run/roadlink-vpn/status.json'), {})
            if routing:
                ap_router.reconcile(command)
            internet = bool(ready and routing and dns_ready(vpn, vpn_state)
                            and routing['dns'] == vpn_state.get('dns')
                            and alive(load_json(Path('/run/roadlink-vpn/controller.json'), {}))
                            and alive(load_json(Path('/run/roadlink-vpn/guard.json'), {})))
            desired_dns = routing['dns'] if internet else None
            if not use_vpn:
                direct = direct_current(subnet, dns_settings(), alive)
                internet = bool(ready and direct)
                desired_dns = direct['dns'] if internet else None
            if desired_dns != advertised_dns:
                dhcp = isolated_dhcp(INTERFACE, subnet, desired_dns).replace(
                    '/run/roadlink/ap.leases', str(ROOT / 'leases'))
                atomic_write(ROOT / 'dnsmasq.conf', dhcp.encode())
                command(['dnsmasq', '--test', '--conf-file=' + str(ROOT / 'dnsmasq.conf')])
                dhcp_process.terminate()
                try:
                    dhcp_process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    dhcp_process.kill()
                    dhcp_process.wait(timeout=2)
                dhcp_process = launch('dnsmasq', ['dnsmasq', '--keep-in-foreground',
                                      '--conf-file=' + str(ROOT / 'dnsmasq.conf')])
                advertised_dns = desired_dns
            write_json(ROOT / 'status.json', {'state': ('VPN_INTERNET' if use_vpn else 'DIRECT_INTERNET') if internet else
                       'LAN_ONLY' if ready else 'STARTING', 'address': address,
                       'ssid': ssid, 'internet': internet, 'dns': advertised_dns or ''})
        time.sleep(2)
    ap.wait(timeout=5)
    dhcp_process.wait(timeout=5)


if __name__ == '__main__':
    if sys.argv[1] == 'child':
        child(sys.argv[2], int(sys.argv[3]), sys.argv[4], sys.argv[5:])
    elif sys.argv[1] == 'guard':
        guard(int(sys.argv[2]), sys.argv[3], int(sys.argv[4]))
    elif sys.argv[1] == 'stop':
        stop()
    elif sys.argv[1] == 'serve':
        serve(sys.argv[2], int(sys.argv[3]), sys.argv[4])
    else:
        raise ValueError('Unknown AP command')
