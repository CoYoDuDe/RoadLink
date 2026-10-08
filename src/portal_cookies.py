"""Bounded transient portal cookies scoped to one exact origin, never persisted."""
from http.cookies import SimpleCookie,CookieError
import re
import time
from email.utils import parsedate_to_datetime
from urllib.parse import urlsplit
from portal_form_fetch import origin


class Jar:
    def __init__(self,clock=time.time):self.values={};self.clock=clock

    def update(self,url,headers):
        if not isinstance(headers,list) or len(headers)>16:raise ValueError('Invalid portal cookies')
        selected=origin(url);parts=urlsplit(url)
        values=dict(self.values)
        for raw in headers:
            if not isinstance(raw,str) or len(raw)>2048 or any(ord(c)<32 or ord(c)>126 for c in raw):
                raise ValueError('Invalid portal cookie')
            parsed=SimpleCookie()
            try:parsed.load(raw)
            except CookieError:raise ValueError('Invalid portal cookie') from None
            if len(parsed)!=1:raise ValueError('Ambiguous portal cookie')
            name,morsel=next(iter(parsed.items()))
            if (not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]{1,128}",name)
                    or any(not 33<=ord(c)<=126 or c in '"(),;\\' for c in morsel.value)):
                raise ValueError('Unsupported portal cookie value')
            domain=morsel['domain'].lstrip('.').lower().rstrip('.')
            if domain and domain!=parts.hostname.lower().rstrip('.'):
                raise ValueError('Portal cookie expands host scope')
            secure=bool(morsel['secure'])
            path=morsel['path'] or (parts.path.rsplit('/',1)[0] or '/')
            if (not path.startswith('/') or len(path)>512 or any(ord(c)<33 or ord(c)>126 or c in ';?\\' for c in path)
                    or secure and parts.scheme!='https'
                    or name.startswith('__Secure-') and not secure
                    or name.startswith('__Host-') and (not secure or domain or path!='/')):
                raise ValueError('Unsupported portal cookie scope')
            age=morsel['max-age']
            if age and not re.fullmatch(r'-?[0-9]{1,10}',age):raise ValueError('Invalid portal cookie lifetime')
            expires=None
            if age:expires=self.clock()+int(age)
            elif morsel['expires']:
                try:
                    stamp=parsedate_to_datetime(morsel['expires'])
                    if stamp.tzinfo is None:raise ValueError()
                    expires=stamp.timestamp()
                except (ValueError,TypeError,OverflowError):raise ValueError('Invalid portal cookie expiry') from None
            key=(selected,path,name)
            if expires is not None and expires<=self.clock():values.pop(key,None)
            else:values[key]={'value':morsel.value,'secure':secure,'expires':expires}
        if len(values)>16 or sum(len(k[2])+len(v['value']) for k,v in values.items())>8192:
            raise ValueError('Portal cookie budget exceeded')
        self.values=values

    def header(self,url):
        parts=urlsplit(url);selected=origin(url);path=parts.path or '/'
        matches=[]
        for (host,scope,name),record in sorted(self.values.items(),key=lambda item:-len(item[0][1])):
            if (host==selected and (path==scope or path.startswith(scope if scope.endswith('/') else scope+'/'))
                    and (record['expires'] is None or record['expires']>self.clock())
                    and (not record['secure'] or parts.scheme=='https')):
                matches.append(name+'='+record['value'])
        if len({p.split('=',1)[0] for p in matches})!=len(matches):
            raise ValueError('Ambiguous overlapping portal cookies')
        return '; '.join(matches)

    def clear(self):self.values.clear()
