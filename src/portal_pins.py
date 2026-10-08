"""Resolve the login page and explicitly approved origins for one bounded session."""
import ipaddress
import math
import re
import time
from urllib.parse import urlsplit
import capport
import portal_dns
import portal_state
import portal_origins
from portal_access import MARK, RADIO


def request(session):
    value = {'id': session['id'], 'connection': session['wan']['connection'],
            'lease': session['wan']['lease'], 'url': session['wan']['url'],
            'hint_hash': session['wan']['hint_hash'], 'expires': session['expires']}
    extras=session.get('additional_urls',[])
    if extras:value['additional_urls']=list(extras)
    portal_origins.urls(value)
    return value


def pending(value, pins, binding, lease, hints, evidence, now):
    try:
        class View:
            pass
        context = View()
        context.binding, context.lease, context.hints = binding, lease, hints
        authorize(value, context, evidence, now)
        matches = pins.get('additional_urls',[])==value.get('additional_urls',[]) and all(pins.get(key) == value.get(key) for key in ('id', 'connection', 'lease', 'url', 'hint_hash'))
        retry = pins.get('retry_after')
        if (matches and pins.get('state') == 'UNAVAILABLE' and type(retry) in (int, float)
                and math.isfinite(retry) and 0 < retry-now <= 10):
            return False
        expiry = pins.get('expires')
        return not (matches and pins.get('state') == 'READY'
                    and type(expiry) in (int, float) and math.isfinite(expiry) and 10 < expiry-now <= 30)
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def authorize(value, context, evidence, now):
    identifier, expiry = value.get('id'), value.get('expires')
    if (not isinstance(identifier, str) or not re.fullmatch(r'[0-9a-f]{24}', identifier)
            or type(expiry) not in (int, float) or not math.isfinite(expiry) or not 0 < expiry-now <= 900
            or value.get('connection') != context.binding
            or value.get('lease') != {key: context.lease.get(key, '') for key in ('address', 'gateway')}
            or value.get('hint_hash') != portal_state.hint_hash(context.hints)):
        raise ValueError('Stale portal target request')
    result = portal_state.current(evidence, context.binding, context.lease, context.hints, now)
    if not result or result.get('state') not in portal_state.CAPTIVE or value.get('url') != result.get('url'):
        raise ValueError('Portal target request does not match current login page')
    portal_origins.urls(value)
    return urlsplit(capport.uri(value['url'], legacy_http=True))


def resolve(value, context, evidence):
    context.check()
    parts = authorize(value, context, evidence, time.monotonic())
    entries,cache=[],{}
    for url in portal_origins.urls(value):
        context.check()
        parts=urlsplit(url)
        host,port=parts.hostname.rstrip('.').lower(),parts.port or (443 if parts.scheme=='https' else 80)
        if port in (22,53,853):raise ValueError('Forbidden portal web port')
        if host not in cache:
            try:addresses,ttl=[str(ipaddress.IPv4Address(host))],30
            except ValueError:
                answer=portal_dns.resolve(host,context.resolvers,str(ipaddress.IPv4Interface(context.lease['address']).ip),
                    RADIO,MARK,context.check,context.permit,min(context.deadline,time.monotonic()+8))
                addresses,ttl=answer['addresses'],answer['ttl']
            if not addresses or not all(capport.allowed_address(address,context.lease,context.vehicle,context.transit) for address in addresses):
                raise ValueError('Protected portal target pin')
            cache[host]=(addresses,ttl)
        addresses,ttl=cache[host]
        entries.append({'url':url,'hostname':host,'addresses':list(addresses),'port':port,'ttl':min(ttl,15)})
    context.check()
    now=time.monotonic()
    expiry=min(value['expires'],now+30)
    if expiry<=now:raise ValueError('Portal session expired while resolving')
    result={'state':'READY','id':value['id'],'connection':context.binding,'lease':value['lease'],
            'hint_hash':value['hint_hash'],'url':value['url'],'ttl':min(entry['ttl'] for entry in entries),'expires':expiry}
    if len(entries)==1:
        result.update({key:entries[0][key] for key in ('hostname','addresses','port')})
    else:
        result.update(additional_urls=list(value['additional_urls']),entries=entries)
    return result
