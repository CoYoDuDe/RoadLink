"""Explicit, bounded extra portal origins; never discover or authorize wildcards."""
from urllib.parse import urlsplit
import capport


def origin(value):
    if not isinstance(value,str):raise ValueError('Invalid portal origin')
    value=value.strip()
    parts=urlsplit(capport.uri(value if '://' in value else 'https://'+value,limit=300,legacy_http=True))
    if parts.path not in ('','/') or parts.query:raise ValueError('Enter an origin without path or query')
    port=parts.port or (443 if parts.scheme=='https' else 80)
    if port in (22,53,853):raise ValueError('Forbidden portal web port')
    host=parts.hostname.rstrip('.').lower()
    suffix='' if port==(443 if parts.scheme=='https' else 80) else ':'+str(port)
    return parts.scheme+'://'+host+suffix+'/'


def approved(values,primary=None):
    if not isinstance(values,list) or len(values)>3:raise ValueError('At most three extra portal origins')
    result=[origin(value) for value in values]
    if len(set(result))!=len(result):raise ValueError('Duplicate portal origin')
    if primary:
        parts=urlsplit(capport.uri(primary,legacy_http=True))
        base=origin(parts.scheme+'://'+parts.netloc)
        if base in result:raise ValueError('Primary portal already approved')
    return result


def parse(text,primary=None):
    if not isinstance(text,str) or len(text.encode())>1000:raise ValueError('Portal origin input too long')
    values=[value.strip() for value in text.replace('\n',',').split(',') if value.strip()]
    return approved(values,primary)


def urls(value):
    primary=capport.uri(value['url'],legacy_http=True)
    extras=value.get('additional_urls',[])
    normalized=approved(extras,primary)
    if normalized!=extras:raise ValueError('Noncanonical portal approvals')
    return [primary]+normalized
