"""Portal session authorization. This module grants no network access by itself."""
import math
import re
from urllib.parse import urlsplit
import capport
import portal_clients
import portal_state
import portal_origins
import wan_lease


def identity(value):
    if (not isinstance(value, dict) or type(value.get('pid')) is not int or value['pid'] <= 0
            or not isinstance(value.get('start'), str) or not value['start'].isascii() or not value['start'].isdecimal()):
        raise ValueError('Invalid portal process identity')
    return {'pid': value['pid'], 'start': value['start']}


def ap_generation(inventory):
    if type(inventory.get('ifindex')) is not int or inventory['ifindex'] <= 0:
        raise ValueError('Invalid portal AP generation')
    return {'controller': identity(inventory['controller']), 'guard': identity(inventory['guard']),
            'ifindex': inventory['ifindex'], 'subnet': inventory['subnet']}


def snapshot(wan, result, now, is_alive):
    binding, lease, hints = wan['connection'], wan['lease'], wan['hints']
    if (not wan_lease.current(lease, binding) or not wan_lease.owned(binding, wan['dhcp'],
            wan['controller'], wan['guard'], wan['state'], is_alive)
            or hints.get('connection') != binding
            or hints.get('lease') != {key: lease.get(key, '') for key in ('address', 'gateway')}):
        raise ValueError('Portal WLAN ownership changed')
    evidence = portal_state.current(result, binding, lease, hints, now)
    if not evidence or evidence.get('state') not in portal_state.CAPTIVE or not evidence.get('url'):
        raise ValueError('No current portal login page')
    return {'connection': dict(binding), 'lease': {key: lease[key] for key in ('address', 'gateway')},
            'controller': identity(wan['controller']), 'guard': identity(wan['guard']),
            'dhcp': identity(wan['dhcp']), 'hint_hash': portal_state.hint_hash(hints),
            'url': capport.uri(evidence['url'], legacy_http=True)}


def create(identifier, device_id, inventory, wan, result, now, is_alive, duration=900, additional_urls=None):
    if not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{24}', identifier):
        raise ValueError('Invalid portal session ID')
    if type(duration) is not int or not 30 <= duration <= 900 or not math.isfinite(now):
        raise ValueError('Invalid portal session duration')
    generation = ap_generation(inventory)
    if not all(is_alive(value) for value in (generation['controller'], generation['guard'])):
        raise ValueError('Vehicle WLAN unavailable')
    device = portal_clients.select(device_id, inventory['clients'])
    value = {'schema': 1, 'id': identifier, 'ap': generation,
            'device': {key: device[key] for key in ('id', 'ip', 'mac')},
            'wan': snapshot(wan, result, now, is_alive), 'started': now, 'expires': now+duration}
    extras=portal_origins.approved([] if additional_urls is None else additional_urls,value['wan']['url'])
    if extras:value['additional_urls']=extras
    return value


def validate_connection(session, inventory, wan, now, is_alive):
    """Check the selected device and transport, without granting portal access.

    The login page may disappear after success. This weaker check is only for
    collecting completion evidence, never for installing or retaining bypass.
    """
    if session.get('schema') != 1 or not isinstance(session.get('id'), str) or not re.fullmatch(r'[0-9a-f]{24}', session['id']):
        raise ValueError('Invalid portal session')
    portal_origins.urls(dict(url=session['wan']['url'],additional_urls=session.get('additional_urls',[])))
    started, expires = session.get('started'), session.get('expires')
    if (any(type(value) not in (int, float) or not math.isfinite(value) for value in (started, expires, now))
            or not 30 <= expires-started <= 900 or not started <= now < expires):
        raise ValueError('Portal session expired')
    if ap_generation(inventory) != session['ap']:
        raise ValueError('Vehicle WLAN generation changed')
    if not all(is_alive(value) for value in (session['ap']['controller'], session['ap']['guard'])):
        raise ValueError('Vehicle WLAN ownership lost')
    device = portal_clients.select(session['device']['id'], inventory['clients'])
    if {key: device[key] for key in ('id', 'ip', 'mac')} != session['device']:
        raise ValueError('Portal login device changed')
    selected = session['wan']
    if (wan['connection'] != selected['connection']
            or not wan_lease.current(wan['lease'], wan['connection'])
            or {key: wan['lease'][key] for key in ('address', 'gateway')} != selected['lease']
            or any(identity(wan[key]) != selected[key] for key in ('controller', 'guard', 'dhcp'))
            or not wan_lease.owned(wan['connection'], wan['dhcp'], wan['controller'],
                                   wan['guard'], wan['state'], is_alive)):
        raise ValueError('Portal WLAN transport changed')
    return session


def validate(session, inventory, wan, result, now, is_alive, internet_proven=False):
    """Recheck before each mutation/reply; successful WiFi Internet revokes bypass."""
    if internet_proven: raise ValueError('Portal login completed')
    validate_connection(session, inventory, wan, now, is_alive)
    if snapshot(wan, result, now, is_alive) != session['wan']:
        raise ValueError('Portal WLAN or login page changed')
    return session


def pin_set(session, pins, now):
    from portal_pins import request
    from portal_router import plan
    expected = request(session)
    expiry, ttl = pins.get('expires'), pins.get('ttl')
    if (pins.get('state') != 'READY'
            or not all(pins.get(key) == expected.get(key) for key in ('id','connection','lease','url','hint_hash'))
            or type(expiry) not in (int,float) or not math.isfinite(expiry) or not 0 < expiry-now <= 30
            or expiry > session['expires'] or not session['started'] <= now < session['expires']
            or type(ttl) is not int or not 0 <= ttl <= 15):
        raise ValueError('Portal target pins are stale')
    from portal_origins import urls
    expected_urls=urls(expected)
    if pins.get('additional_urls',[])!=expected.get('additional_urls',[]):
        raise ValueError('Portal origin approvals changed')
    if len(expected_urls)==1:
        entries=[dict(url=expected_urls[0],hostname=pins.get('hostname'),port=pins.get('port'),
                      addresses=pins.get('addresses'),ttl=ttl)]
        if 'entries' in pins:raise ValueError('Unexpected extra portal targets')
    else:
        entries=pins.get('entries')
        if not isinstance(entries,list) or len(entries)!=len(expected_urls):
            raise ValueError('Incomplete approved portal target set')
    endpoints,dns=[],{}
    for url,entry in zip(expected_urls,entries):
        if not isinstance(entry,dict):raise ValueError('Invalid portal target record')
        parts=urlsplit(url)
        host,port=parts.hostname.rstrip('.').lower(),parts.port or (443 if parts.scheme=='https' else 80)
        addresses=entry.get('addresses');entry_ttl=entry.get('ttl')
        if (set(entry)!={'url','hostname','port','addresses','ttl'} or entry.get('url')!=url
                or entry.get('hostname')!=host or type(entry.get('port')) is not int or entry['port']!=port
                or not isinstance(addresses,list) or not 1<=len(addresses)<=8
                or type(entry_ttl) is not int or not 0<=entry_ttl<=15):
            raise ValueError('Portal target pins differ from approved origins')
        endpoints.extend({'address':value,'port':port} for value in addresses)
        record={'addresses':list(addresses),'expires':expiry,'ttl':entry_ttl}
        if host in dns and dns[host]!=record:raise ValueError('Conflicting portal DNS pins')
        dns[host]=record
    plan(session['ap']['subnet'],session['device'],session['wan']['lease'],endpoints,session['wan']['lease']['gateway'])
    return {'endpoints':endpoints,'dns':dns}
