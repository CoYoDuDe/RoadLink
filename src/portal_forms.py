"""Bounded static-form inspection, without JavaScript, network or submission.

Field classifications are a local, explicitly reviewed adapter specification.
A page cannot declare itself trusted/free. Dynamic/vendor-specific forms need
their own adapter; this module never interprets an operator's authentication API.
"""
import json
from html.parser import HTMLParser
from urllib.parse import urljoin, urlencode
import portal_known

VOID = {'area','base','br','col','embed','hr','img','input','link','meta','param','source','track','wbr'}
ACTIVE = {'script','iframe','frame','frameset','object','embed','applet','svg','math','template','base'}
TOKENS = {'csrf','_csrf','csrf_token','_csrf_token'}


class Inspection(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.stack=[]
        self.forms=[]
        self.current=None
        self.structure=[]
        self.words=[]
        self.manual=False
        self.count=0

    def handle_starttag(self,tag,attributes):
        self.count+=1
        if self.count>2048 or len(self.stack)>64 or len(attributes)>32:
            raise ValueError('Portal HTML limits exceeded')
        attrs=dict(attributes)
        if len(attrs)!=len(attributes):raise ValueError('Ambiguous HTML attributes')
        if tag in ACTIVE or any(k.startswith('on') for k in attrs):self.manual=True
        if tag=='a' and attrs.get('href') and not attrs['href'].startswith('#'):
            # Linked terms can change independently of this document. Until a
            # bound terms fetcher fingerprints them, they require manual review.
            self.manual=True
        if tag=='meta' and attrs.get('http-equiv','').lower()=='refresh':self.manual=True
        if any(k in attrs for k in ('form','formaction','formmethod','formtarget','formenctype')):
            self.manual=True
        if tag=='form':
            if self.current is not None or len(self.forms)>=8:
                raise ValueError('Nested or excessive portal forms')
            self.current={'attrs':attrs,'fields':[]}
            self.forms.append(self.current)
        if tag in ('input','button','select','textarea'):
            if self.current is None:self.manual=True
            else:
                kind=attrs.get('type','submit' if tag=='button' else 'text').lower()
                if tag in ('select','textarea'):kind=tag
                name=attrs.get('name','')
                if not name or any(f['name']==name for f in self.current['fields']):
                    raise ValueError('Missing or duplicate portal control name')
                if len(self.current['fields'])>=32:raise ValueError('Too many portal controls')
                self.current['fields'].append({'name':name,'type':kind,
                    'required':'required' in attrs,'value':attrs.get('value',''),
                    'disabled':'disabled' in attrs})
        fingerprint_attrs=dict(attrs)
        # Only explicitly named CSRF fields may vary without changing structure.
        # All other hidden values (price, choice, tariff, destination) stay hashed.
        if tag=='input' and attrs.get('type','').lower()=='hidden' and attrs.get('name') in TOKENS:
            fingerprint_attrs['value']='[fresh-session-token]'
        self.structure.append(['start',tag,sorted(fingerprint_attrs.items())])
        if tag not in VOID:self.stack.append(tag)

    def handle_startendtag(self,tag,attrs):
        self.handle_starttag(tag,attrs)
        if tag not in VOID:self.handle_endtag(tag)

    def handle_endtag(self,tag):
        if tag in VOID:raise ValueError('Ambiguous void element closure')
        if not self.stack or self.stack.pop()!=tag:
            raise ValueError('HTML requires browser-specific repair')
        if tag=='form':self.current=None
        self.structure.append(['end',tag])

    def handle_data(self,data):
        if data.strip():self.words.append(data)

    def handle_comment(self,data):
        # Include conditional/hidden instructions in the change fingerprint.
        self.structure.append(['comment',data])
        if data.lstrip().lower().startswith('[if'):self.manual=True

    def handle_decl(self,decl):
        if decl.lower()!='doctype html':self.manual=True

    def handle_pi(self,data):self.manual=True
    def unknown_decl(self,data):self.manual=True


def inspect(html):
    if (not isinstance(html,str) or not html or len(html.encode())>65536
            or '\x00' in html):raise ValueError('Invalid portal HTML body')
    parser=Inspection()
    parser.feed(html);parser.close()
    if parser.stack or parser.current is not None or not parser.forms:
        raise ValueError('Incomplete portal HTML')
    return parser


def descriptor(html,url,radio,review,redirects):
    """Return an observation for KnownPortals, never an approval or login plan.

    review contains only form index, allowed action and explicit field roles;
    it must come from local manual review, never JSON or attributes in a page.
    URL redirects and radio identity come from the connection-bound fetcher.
    """
    if (not isinstance(review,dict) or set(review)!={'form_index','action','roles'}
            or type(review['form_index']) is not int or not isinstance(review['roles'],dict)
            or not isinstance(radio,dict) or set(radio)!={'ssid','bssids','wan_mac'}):
        raise ValueError('Explicit local portal review required')
    parser=inspect(html)
    if not 0<=review['form_index']<len(parser.forms):raise ValueError('Reviewed form disappeared')
    form=parser.forms[review['form_index']]
    attrs=form['attrs']
    if attrs.get('target','') not in ('','_self') or attrs.get('enctype','application/x-www-form-urlencoded').lower()!='application/x-www-form-urlencoded':
        parser.manual=True
    fields=[]
    reasons=set()
    if parser.manual:reasons.add('unknown')
    for field in form['fields']:
        kind,name=field['type'],field['name']
        role=review['roles'].get(name,'unknown')
        if kind in ('email','password','file','text','textarea','select','number','date','radio'):
            role='phone' if kind=='tel' else 'personal_data'
        elif kind=='tel':role='phone'
        elif kind=='hidden':
            if name not in TOKENS or role!='session':role='unknown'
        elif kind=='checkbox':
            if role not in {'consent'}|portal_known.MANUAL:role='unknown'
        elif kind=='submit':
            if role!='submit':role='unknown'
        else:role='unknown'
        if field['disabled']:reasons.add('unknown')
        if role in portal_known.MANUAL:reasons.add(role)
        fields.append({key:field[key] for key in ('name','type','required')}|{'role':role})
    if set(review['roles'])!={f['name'] for f in fields}:reasons.add('unknown')
    value=dict(radio,adapter='static-html-form-v1',url=url,
        form_action=urljoin(url,attrs.get('action') or url),method=attrs.get('method','GET').upper(),
        fields=fields,redirects=redirects,success_detection='bound-dns-tls-vpn-v1',
        structure=json.dumps(parser.structure,ensure_ascii=False,sort_keys=True),
        terms=' '.join(parser.words),manual_reasons=sorted(reasons),action=review['action'])
    # Validate now; the caller still needs explicit manual success and approval.
    portal_known.descriptor(value)
    return value


def prepare(html,url,radio,review,redirects,store):
    """Prepare one previously approved static action; caller must bind delivery.

    Returned data can contain a fresh CSRF token and must never be persisted or
    logged. Preparing does not submit it or prove ownership/Internet. The sender
    must recheck current connection identity and pinned destinations immediately
    before sending, and discard this result when that generation changes.
    """
    observed=descriptor(html,url,radio,review,redirects)
    decision=store.decision(observed)
    if decision!='AUTO_ACCEPT_READY':raise ValueError(decision)
    form=inspect(html).forms[review['form_index']]
    if sum(f['type']=='submit' for f in form['fields'])!=1:
        raise ValueError('Ambiguous static submit action')
    consent=any(review['roles'][f['name']]=='consent' for f in form['fields'])
    if consent and review['action']!='terms_checkbox':
        raise ValueError('Checkbox approval requires explicit terms action')
    pairs=[]
    for field in form['fields']:
        value=field['value']
        if field['type']=='hidden' and (not value or len(value.encode())>2048):
            raise ValueError('Missing or excessive fresh session token')
        if field['type']=='checkbox' and not value:value='on'
        pairs.append((field['name'],value))
    body=urlencode(pairs).encode('ascii')
    if len(body)>8192:raise ValueError('Portal action too large')
    return {'url':observed['form_action'],'method':observed['method'],
            'content_type':'application/x-www-form-urlencoded','body':body,
            'fingerprint':portal_known.digest(portal_known.descriptor(observed))}
