"""Hash-only static-form candidate; explicit local approval is still required.

This recognises a form shape, never a provider's claim that access is free.
Scripts, linked terms, personal fields and ambiguous choices stay manual.
"""
import re
from urllib.parse import urlsplit
import portal_forms
import portal_known
CONSENT_NAMES={'terms','accept_terms','agree','agreement','accept','tos','conditions','termsAccepted'}


def observe(page, radio):
    try:
        parser=portal_forms.inspect(page['html'])
        if parser.manual or len(parser.forms)!=1:return None
        fields=parser.forms[0]['fields']
        if sum(f['type']=='submit' for f in fields)!=1 or sum(f['type']=='checkbox' for f in fields)>1:
            return None
        roles={}
        for field in fields:
            if field['disabled']:return None
            if field['type']=='hidden' and field['name'] in portal_forms.TOKENS:role='session'
            elif field['type']=='checkbox' and field['name'] in CONSENT_NAMES:role='consent'
            elif field['type']=='submit':role='submit'
            else:return None
            roles[field['name']]=role
        # Financial/identity challenges require a provider-specific manual path.
        words=' '.join(parser.words)
        if re.search(r'(?i)\b(payment|purchase|buy|credit\s*card|captcha|sms|mfa|newsletter|zahlung|kaufen|kreditkarte|gebuehr|gebühr)\b|[$€£]|\b\d+[.,]\d{2}\s*(eur|usd|gbp)\b',words):
            return None
        action='terms_checkbox' if 'consent' in roles.values() else 'connect_button'
        review={'form_index':0,'action':action,'roles':roles}
        observed=portal_forms.descriptor(page['html'],page['url'],radio,review,page['redirects'])
        snapshot=portal_known.descriptor(observed)
        if snapshot['manual_reasons']:return None
        for value in (snapshot['url'],snapshot['form_action'],*snapshot['redirects']):
            # Generic static adapter cannot identify session tokens in paths.
            # Keep only simple static paths; dynamic paths need a vendor adapter.
            if any(not re.fullmatch(r'[a-z._-]{1,32}',part) for part in urlsplit(value).path.split('/') if part):
                return None
        return {'descriptor':snapshot,'fingerprint':portal_known.digest(snapshot),'review':review}
    except (ValueError,KeyError,TypeError):return None


def validate(value):
    if not isinstance(value,dict) or set(value)!={'descriptor','fingerprint','review'}:
        raise ValueError('Invalid portal candidate')
    snapshot=portal_known.stored_snapshot(value['descriptor'])
    review=value['review']
    if (snapshot['adapter']!='static-html-form-v1' or snapshot['manual_reasons']
            or value['fingerprint']!=portal_known.digest(snapshot)
            or not isinstance(review,dict) or set(review)!={'form_index','action','roles'}
            or review['form_index']!=0 or type(review['form_index']) is not int
            or review['action']!=snapshot['action']
            or review['roles']!={f['name']:f['role'] for f in snapshot['fields']}):
        raise ValueError('Inconsistent portal candidate')
    fields=snapshot['fields']
    if (sum(f['type']=='submit' and f['role']=='submit' for f in fields)!=1
            or sum(f['type']=='checkbox' for f in fields)>1
            or any(not (f['type']=='submit' and f['role']=='submit'
                        or f['type']=='checkbox' and f['name'] in CONSENT_NAMES and f['role']=='consent'
                        or f['type']=='hidden' and f['name'] in portal_forms.TOKENS and f['role']=='session') for f in fields)):
        raise ValueError('Unsupported candidate controls')
    return snapshot
