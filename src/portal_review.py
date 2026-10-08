"""Read-only form observation for one live, explicitly started portal session.

No HTML, field values, cookies or session URLs enter the result. A successful
inspection is not approval, a login attempt, or evidence of Internet access.
"""
import copy
import hashlib
import json
import math
import time
import portal_forms
import portal_form_fetch
import portal_pins
import portal_candidate


def matching(request, result):
    return (isinstance(result, dict) and result.get('request_hash') == digest(request))


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


def current(request, result, binding, lease, hints, evidence, now):
    class View: pass
    context = View()
    context.binding, context.lease, context.hints = binding, lease, hints
    try:
        portal_pins.authorize(request, context, evidence, now)
        stamp = result.get('checked_at')
        if (matching(request, result) and type(stamp) in (int, float) and math.isfinite(stamp)
                and 0 <= now-stamp < 30 and result.get('state') in ('OBSERVED', 'MANUAL_REQUIRED', 'UNAVAILABLE')):
            return result
    except (ValueError, TypeError, KeyError, AttributeError): pass
    return None


def pending(request, result, binding, lease, hints, evidence, now):
    class View: pass
    context = View()
    context.binding, context.lease, context.hints = binding, lease, hints
    try:
        portal_pins.authorize(request, context, evidence, now)
        return current(request, result, binding, lease, hints, evidence, now) is None
    except (ValueError, TypeError, KeyError, AttributeError):
        return False


def inspect(request, context, evidence, session_check):
    """The caller rechecks its request and session guard before every socket use."""
    initial = copy.deepcopy(request)

    def check():
        context.check()
        session_check()
        if request != initial: raise RuntimeError('Portal review request changed')
        # Refresh evidence through the caller; a browser's newer portal URL is
        # never silently substituted for the originally selected page.
        portal_pins.authorize(initial, context, evidence(), time.monotonic())

    check()
    class Bound:
        def __getattr__(self, name): return getattr(context, name)
        def check(self): check()
    page = portal_form_fetch.fetch(initial['url'], Bound(), initial.get('additional_urls', []))
    check()
    parser = portal_forms.inspect(page['html'])
    forms = []
    for index, form in enumerate(parser.forms):
        fields = []
        for field in form['fields']:
            if (len(field['name'].encode()) > 128 or len(field['type'].encode()) > 32
                    or any(ord(c) < 32 for c in field['name'] + field['type'])):
                raise ValueError('Unsupported portal control metadata')
            # These are observations for a future explicit local review, not
            # classifications authorizing consent or credentials.
            fields.append({key: field[key] for key in ('name', 'type', 'required', 'disabled')})
        attrs = form['attrs']
        forms.append({'index': index, 'method': attrs.get('method', 'GET').upper(), 'fields': fields})
    result = {'state': 'MANUAL_REQUIRED' if parser.manual else 'OBSERVED',
              'request_hash': digest(initial), 'checked_at': time.monotonic(),
              'structure_hash': digest(parser.structure), 'terms_hash': digest(' '.join(parser.words)),
              'forms': forms}
    # No raw target URLs (often session-bearing) in diagnostics or records.
    result['redirect_hashes'] = [digest(url) for url in page['redirects']]
    radio = getattr(context, 'radio_identity', None)
    if radio is not None:
        candidate = portal_candidate.observe(page, radio())
        if candidate is not None: result['candidate'] = candidate
    check()
    return result
