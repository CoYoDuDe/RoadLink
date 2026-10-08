#!/usr/bin/env python3
"""One-shot CAPPORT worker in the owned WAN namespace; never enables forwarding."""
from contextlib import contextmanager
import ipaddress
import json
import os
from pathlib import Path
import subprocess
import time
from ap_runtime import alive, token
from storage import load_json, write_json
import capport
import portal_access
import portal_fetch
import portal_legacy
import portal_state
import portal_pins
import portal_review
import wan_lease
import portal_auto
import portal_known

ROOT = Path('/run/roadlink-wan')
NS = 'roadlink-wan'


def namespace(state):
    own = os.stat('/proc/self/ns/net')
    handle = Path('/run/netns') / NS
    if handle.is_symlink() or not handle.exists(): raise RuntimeError('Portal namespace unavailable')
    expected = state.get('namespace_inode'), state.get('namespace_device')
    if ((own.st_ino, own.st_dev) != expected
            or (handle.stat().st_ino, handle.stat().st_dev) != expected
            or own.st_ino == os.stat('/proc/1/ns/net').st_ino):
        raise RuntimeError('Portal namespace ownership changed')
    links = json.loads(subprocess.run(['ip', '-j', 'link', 'show', 'dev', portal_access.RADIO],
        check=True, capture_output=True, timeout=2).stdout)
    if len(links) != 1 or links[0].get('ifindex') != state.get('ifindex'):
        raise RuntimeError('Portal radio changed')


def cleanup():
    journal = load_json(ROOT / 'portal-rules.json', {})
    if not journal: return
    state = load_json(ROOT / 'state.json', {})
    if journal.get('namespace') != {key: state.get(key) for key in ('namespace_inode', 'namespace_device', 'ifindex')}:
        raise RuntimeError('Foreign portal rule journal retained')
    namespace(state)
    owner = journal.get('owner', {})
    if alive(owner) and owner.get('pid') != os.getpid():
        raise RuntimeError('Another portal worker still owns rules')
    # Regenerate rules from validated socket data; never execute journal argv.
    for arguments in reversed(journal.get('sockets', [])):
        for chain, args in reversed(portal_access.rules(**arguments)):
            base = ['iptables', '-w', '1', '-t', 'filter']
            while subprocess.run(base+['-C', chain, *args], capture_output=True, timeout=2).returncode == 0:
                subprocess.run(base+['-D', chain, *args], check=True, capture_output=True, timeout=2)
    write_json(ROOT / 'portal-rules.json', {})


class Context:
    def __init__(self):
        self.state = load_json(ROOT / 'state.json', {})
        self.binding = load_json(ROOT / 'connection.json', {})
        self.lease = load_json(ROOT / 'lease.json', {})
        self.hints = load_json(ROOT / 'portal-hints.json', {})
        self.owner = {'pid': os.getpid(), 'start': token(os.getpid())}
        self.deadline = time.monotonic() + 20
        self.check()
        ap = load_json(Path('/run/roadlink-ap/status.json'), {})
        self.vehicle = str(ipaddress.IPv4Network(ap['address'] + '/24', strict=False))
        self.transit = self.state.get('bridge', {}).get('subnet', '172.27.250.0/30')
        self.resolvers = self.hints.get('dns', [])[:4]

    def check(self):
        if time.monotonic() >= self.deadline or (ROOT / 'stop').exists() or (ROOT / 'cleaning').exists():
            raise RuntimeError('Portal connection stopped')
        if (load_json(ROOT / 'portal.json', {}) != self.owner
                or load_json(ROOT / 'connection.json', {}) != self.binding
                or load_json(ROOT / 'lease.json', {}) != self.lease
                or load_json(ROOT / 'portal-hints.json', {}) != self.hints
                or not wan_lease.current(self.lease, self.binding)
                or self.hints.get('connection') != self.binding
                or self.hints.get('lease') != {key: self.lease.get(key, '') for key in ('address', 'gateway')}
                or not wan_lease.owned(self.binding, load_json(ROOT / 'dhcp.json', {}),
                    load_json(ROOT / 'controller.json', {}), load_json(ROOT / 'guard.json', {}), self.state, alive)):
            raise RuntimeError('Portal connection ownership changed')
        namespace(self.state)
        result = subprocess.run(['wpa_cli', '-p', str(ROOT / 'control'), '-i', portal_access.RADIO, 'status'],
                                capture_output=True, text=True, check=True, timeout=2)
        status = dict(line.split('=', 1) for line in result.stdout.splitlines() if '=' in line)
        if status.get('wpa_state') != 'COMPLETED' or status.get('bssid', '').lower() != self.binding.get('bssid'):
            raise RuntimeError('Portal WLAN association changed')

    def radio_identity(self):
        """Read actual associated SSID/private WAN MAC, never profile credentials."""
        self.check()
        links=json.loads(subprocess.run(['ip','-j','link','show','dev',portal_access.RADIO],
            check=True,capture_output=True,text=True,timeout=2).stdout)
        response=subprocess.run(['wpa_cli','-p',str(ROOT/'control'),'-i',portal_access.RADIO,'status'],
            check=True,capture_output=True,text=True,timeout=2).stdout
        fields={}
        for line in response.splitlines():
            if '=' not in line:continue
            key,value=line.split('=',1)
            if key in fields:raise ValueError('Ambiguous WLAN identity')
            fields[key]=value
        if (len(links)!=1 or links[0].get('ifindex')!=self.binding['ifindex']
                or fields.get('wpa_state')!='COMPLETED'
                or fields.get('bssid','').lower()!=self.binding['bssid']):
            raise RuntimeError('Portal WLAN identity changed')
        value={'ssid':fields['ssid'],'bssids':[self.binding['bssid']],'wan_mac':links[0]['address']}
        self.check()
        return value

    @contextmanager
    def permit(self, sock, address, remote_port, protocol):
        self.check()
        source, local_port = sock.getsockname()[:2]
        arguments = dict(source=source, local_port=local_port, address=address,
                         remote_port=remote_port, protocol=protocol, lease=self.lease,
                         resolvers=self.resolvers, vehicle_subnet=self.vehicle, transit_subnet=self.transit)
        rules = portal_access.rules(**arguments)
        journal = {'owner': self.owner,
                   'namespace': {key: self.state[key] for key in ('namespace_inode', 'namespace_device', 'ifindex')},
                   'sockets': [arguments]}
        if load_json(ROOT / 'portal-rules.json', {}): raise RuntimeError('Portal permissions not drained')
        write_json(ROOT / 'portal-rules.json', journal)  # precedes every allowance
        try:
            for chain, args in rules:
                self.check()
                subprocess.run(['iptables', '-w', '1', '-t', 'filter', '-I', chain, '1', *args],
                               check=True, capture_output=True, timeout=2)
            self.check()
            yield
        finally:
            cleanup()


def review_session(request):
    """Recheck the manual session's live owners and immutable daemon intent."""
    import portal_request
    import portal_session_runtime as session_runtime
    session_runtime.private_root()
    session = load_json(session_runtime.ROOT/'session.json', {})
    if portal_pins.request(session) != request:
        raise RuntimeError('Portal review session changed')
    portal_request.check(session, alive)
    if session_runtime.stopped() or not all(alive(load_json(session_runtime.ROOT/(name+'.json'), {}))
                                          for name in ('controller', 'guard')):
        raise RuntimeError('Portal review session stopped')
    ap_root = Path('/run/roadlink-ap')
    if (any((ap_root/name).exists() for name in ('stop', 'cleaning'))
            or any(load_json(ap_root/(name+'.json'), {}) != session['ap'][name]
                   or not alive(session['ap'][name]) for name in ('controller', 'guard'))
            or load_json(ap_root/'radio.json', {}).get('ap_ifindex') != session['ap']['ifindex']):
        raise RuntimeError('Portal review vehicle WLAN changed')


def main(resolve_targets=False, review_form=False, auto_form=False):
    context = None
    request = None
    try:
        context = Context()
        if auto_form:
            import portal_session_runtime
            def check_auto():
                context.check()
                if portal_session_runtime.busy():raise RuntimeError('Manual portal session owns admission')
                evidence=portal_state.current(load_json(ROOT/'portal-result.json',{}),context.binding,
                    context.lease,context.hints,time.monotonic())
                if not evidence or evidence.get('state') not in portal_state.CAPTIVE or evidence.get('url')!=url:
                    raise RuntimeError('Automatic portal evidence changed')
            evidence=portal_state.current(load_json(ROOT/'portal-result.json',{}),context.binding,
                context.lease,context.hints,time.monotonic())
            if not evidence or not evidence.get('url'):return
            url=evidence['url'];radio=context.radio_identity();store=portal_known.KnownPortals()
            check_auto()
            if not portal_auto.pending(evidence,radio,store,load_json(ROOT/'portal-auto-result.json',{}),context.binding,context.lease):return
            selected=portal_auto.eligible(url,radio,store)
            marker={'state':'STARTED','connection':context.binding,
                'lease':{k:context.lease[k] for k in ('address','gateway')},
                'fingerprint':selected[1]['fingerprint'],'target_hash':portal_known.digest(url),'checked_at':time.monotonic()}
            write_json(ROOT/'portal-auto-result.json',marker)  # Precedes GET and any possible action.
            class Bound:
                def __getattr__(self,name):return getattr(context,name)
                def check(self):check_auto()
            result=portal_auto.attempt(url,Bound(),radio,store)
            context.check()
            write_json(ROOT/'portal-auto-result.json',dict(marker,**result))
            return
        if review_form:
            request = load_json(ROOT/'portal-review-request.json', {})
            def check_session():
                if load_json(ROOT/'portal-review-request.json', {}) != request:
                    raise RuntimeError('Portal review request revoked')
                review_session(request)
            result = portal_review.inspect(request, context,
                lambda: load_json(ROOT/'portal-result.json', {}), check_session)
            context.check()
            check_session()
            write_json(ROOT/'portal-review-result.json', result)
            return
        if resolve_targets:
            request = load_json(ROOT/'portal-resolve-request.json', {})
            result = portal_pins.resolve(request, context, load_json(ROOT/'portal-result.json', {}))
            context.check()
            if load_json(ROOT/'portal-resolve-request.json', {}) != request:
                raise RuntimeError('Portal target request changed')
            write_json(ROOT/'portal-pins.json', result)
            return
        api = context.hints.get('api', '')
        metadata = legacy = None
        if api and api != capport.UNRESTRICTED:
            try:
                metadata = portal_fetch.fetch(api, context.lease, context.resolvers, context.vehicle, context.transit,
                    portal_access.RADIO, portal_access.MARK, context.check, context.permit,
                    min(context.deadline, time.monotonic()+8))
            except (ValueError, OSError):
                context.check()
        # This is a separate fixed discovery URL, never a downgrade of an API
        # or login URL. Compare signals even when the API says unrestricted.
        try:
            legacy = portal_legacy.probe(context.lease, context.resolvers, context.vehicle, context.transit,
                portal_access.RADIO, portal_access.MARK, context.check, context.permit,
                min(context.deadline, time.monotonic()+8))
        except (ValueError, OSError): context.check()
        result = portal_state.combine(metadata, legacy)
        context.check()
        write_json(ROOT / 'portal-result.json', dict(result, connection=context.binding,
            lease={key: context.lease[key] for key in ('address', 'gateway')}, checked_at=time.monotonic(),
            hint_hash=portal_state.hint_hash(context.hints)))
    except (ValueError, OSError, RuntimeError, KeyError, TypeError, subprocess.SubprocessError):
        # Neither hostile response bodies nor session URLs enter diagnostics.
        if context is not None and auto_form:
            # Retain STARTED even on an uncertain POST response/crash. Neither
            # an exception nor a timeout may silently trigger a second action.
            pass
        elif context is not None and review_form and request is not None:
            try:
                context.check()
                if load_json(ROOT/'portal-review-request.json', {}) == request:
                    review_session(request)
                    write_json(ROOT/'portal-review-result.json', {'state': 'UNAVAILABLE',
                        'request_hash': portal_review.digest(request), 'checked_at': time.monotonic()})
            except (ValueError, OSError, RuntimeError, KeyError, subprocess.SubprocessError): pass
        elif context is not None and resolve_targets and request is not None:
            try:
                context.check()
                if load_json(ROOT/'portal-resolve-request.json', {}) == request:
                    write_json(ROOT/'portal-pins.json', dict(request, state='UNAVAILABLE', retry_after=time.monotonic()+10))
            except (ValueError, OSError, RuntimeError, subprocess.SubprocessError): pass
        elif context is not None:
            try:
                context.check()
                write_json(ROOT / 'portal-result.json', {'state': 'UNAVAILABLE', 'connection': context.binding})
            except (ValueError, OSError, RuntimeError, subprocess.SubprocessError): pass
    finally:
        cleanup()


if __name__ == '__main__':
    import sys
    if len(sys.argv) == 2 and sys.argv[1] == 'cleanup': cleanup()
    elif len(sys.argv) == 2 and sys.argv[1] == 'resolve': main(resolve_targets=True)
    elif len(sys.argv) == 2 and sys.argv[1] == 'review': main(review_form=True)
    elif len(sys.argv) == 2 and sys.argv[1] == 'auto': main(auto_form=True)
    elif len(sys.argv) == 1: main()
    else: raise ValueError('Unexpected portal command')
