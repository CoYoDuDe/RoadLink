"""Bounded static login attempt for a previously explicitly approved portal.

The guarded WAN caller owns scheduling and independent post-login probes.
SUBMITTED is not successful login, Internet readiness or a new approval.
"""
import copy
import time
from urllib.parse import urlsplit
import portal_candidate
import portal_forms
import portal_http
import portal_known
import portal_form_fetch
import portal_state


def eligible(url,radio,store):
    try:
        url=portal_known.location(url)
        data=store.read()
        if not data['auto_accept']:return None
        records=[]
        for identifier,record in data['profiles'].items():
            snapshot=record['descriptor']
            if (record['auto_accept'] and snapshot['adapter']=='static-html-form-v1'
                    and snapshot['ssid']==radio['ssid'] and snapshot['wan_mac']==radio['wan_mac']
                    and radio['bssids']==[b for b in snapshot['bssids'] if b in radio['bssids']]
                    and snapshot['url']==url):
                records.append((identifier,copy.deepcopy(record)))
        return records[0] if len(records)==1 else None
    except (ValueError,KeyError,TypeError,OSError):return None


def pending(evidence,radio,store,previous,binding,lease):
    if not evidence or evidence.get('state') not in portal_state.CAPTIVE or not evidence.get('url'):return False
    selected=eligible(evidence['url'],radio,store)
    if selected is None:return False
    fingerprint=selected[1]['fingerprint']
    # One attempt per connection/action, including lost responses or crashes.
    # A delayed observation never authorizes replay of an uncertain action.
    return not (previous.get('connection')==binding
        and previous.get('lease')=={k:lease.get(k,'') for k in ('address','gateway')}
        and previous.get('fingerprint')==fingerprint
        and previous.get('target_hash')==portal_known.digest(evidence['url']))


def attempt(url,context,radio,store=None):
    store=portal_known.KnownPortals() if store is None else store
    selected=eligible(url,radio,store)
    if selected is None:return {'state':'MANUAL_REQUIRED'}
    identifier,record=selected;expected=record['fingerprint']
    radio=copy.deepcopy(radio)
    def authorize():
        current=eligible(url,radio,store)
        if current is None or current[0]!=identifier or current[1]['fingerprint']!=expected:
            raise RuntimeError('Portal approval revoked or changed')
    # Previously approved action and observed redirects are the only possible
    # extra origins. No portal response can silently expand this set.
    snapshot=record['descriptor']
    origins=sorted({portal_form_fetch.origin(v) for v in (snapshot['form_action'],*snapshot['redirects'])}
                   -{portal_form_fetch.origin(url)})
    with portal_http.Session(url,context,authorize,origins) as session:
        page=session.fetch()
        candidate=portal_candidate.observe(page,radio)
        if candidate is None or candidate['fingerprint']!=expected:
            return {'state':'PORTAL_CHANGED'}
        plan=portal_forms.prepare(page['html'],page['url'],radio,candidate['review'],page['redirects'],store)
        if plan['fingerprint']!=expected:raise ValueError('Prepared action differs from approval')
        authorize()
        parts=urlsplit(plan['url'])
        # Generic static adapter knows only these same-origin completion pages.
        # Other provider paths need their own explicitly reviewed continuation.
        continuations=[parts.scheme+'://'+parts.netloc+path for path in ('/done','/success')]
        session.submit(plan,continuations)
        context.check()
        return {'state':'SUBMITTED','fingerprint':expected,'checked_at':time.monotonic()}
