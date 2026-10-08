"""One owned transient portal HTTP session; submission never proves Internet.

No native DNS, cookie persistence, TLS downgrade or automatic replay after a
possibly delivered action. Authorization is rechecked immediately before send.
"""
import copy
import ipaddress
import re
import socket
import ssl
from urllib.parse import urljoin,urlsplit
import capport
import portal_access
import portal_cookies
import portal_form_fetch
import portal_origins
from portal_dns import remaining,resolve
from portal_fetch import receive
from probe_binding import bind_path


class Session:
    def __init__(self,url,context,authorize,additional_origins=None):
        self.url=capport.uri(url,legacy_http=True)
        self.context,self.authorize=context,authorize
        self.allowed={portal_form_fetch.origin(self.url),*portal_origins.approved(
            [] if additional_origins is None else additional_origins,self.url)}
        self.initial=copy.deepcopy({key:getattr(context,key) for key in
            ('binding','lease','resolvers','vehicle','transit','deadline')})
        self.jar=portal_cookies.Jar()
        self.closed=False
        self.check()

    def check(self):
        if self.closed:raise RuntimeError('Portal HTTP session closed')
        self.context.check()
        if any(getattr(self.context,key)!=value for key,value in self.initial.items()):
            self.jar.clear()
            raise RuntimeError('Portal HTTP generation changed')
        self.authorize()

    def close(self):self.jar.clear();self.closed=True

    def __enter__(self):return self
    def __exit__(self,*_):self.close()

    def exchange(self,url,method='GET',body=b''):
        self.check()
        url=capport.uri(url,legacy_http=True);parts=urlsplit(url)
        if (portal_form_fetch.origin(url) not in self.allowed
                or urlsplit(self.url).scheme=='https' and parts.scheme!='https'):
            raise ValueError('Portal target not approved')
        if method not in ('GET','POST') or not isinstance(body,bytes) or len(body)>8192 or method=='GET' and body:
            raise ValueError('Invalid portal HTTP action')
        lease=self.initial['lease'];source=str(ipaddress.IPv4Interface(lease['address']).ip)
        try:addresses=[str(ipaddress.IPv4Address(parts.hostname))]
        except ValueError:
            addresses=resolve(parts.hostname,self.initial['resolvers'],source,portal_access.RADIO,
                portal_access.MARK,self.check,self.context.permit,self.initial['deadline'])['addresses']
        self.check()
        if (not addresses or len(addresses)>8 or not all(capport.allowed_address(a,lease,
                self.initial['vehicle'],self.initial['transit']) for a in addresses)):
            raise ValueError('Forbidden portal HTTP destination')
        path=parts.path or '/'
        if parts.query:path+='?'+parts.query
        headers=[method+' '+path+' HTTP/1.1','Host: '+parts.netloc,'Accept: text/html',
                 'Accept-Encoding: identity','Connection: close']
        cookie=self.jar.header(url)
        if cookie:headers.append('Cookie: '+cookie)
        if method=='POST':headers+=['Content-Type: application/x-www-form-urlencoded','Content-Length: '+str(len(body))]
        payload=('\r\n'.join(headers)+'\r\n\r\n').encode('ascii')+body
        if len(payload)>16384:raise ValueError('Portal HTTP request too large')
        port=parts.port or (443 if parts.scheme=='https' else 80)
        secure_context=None
        if parts.scheme=='https':
            secure_context=ssl.create_default_context()
            secure_context.minimum_version=ssl.TLSVersion.TLSv1_2
        # One numeric destination only: a failed response must not repeat an
        # action that the first server may already have processed.
        with socket.socket(socket.AF_INET,socket.SOCK_STREAM) as sock:
            sock.settimeout(remaining(self.initial['deadline'],self.check))
            bind_path(sock,source,portal_access.RADIO,portal_access.MARK)
            with self.context.permit(sock,addresses[0],port,'tcp'):
                sock.settimeout(remaining(self.initial['deadline'],self.check))
                sock.connect((addresses[0],port))
                self.check()
                def send(stream):
                    stream.settimeout(remaining(self.initial['deadline'],self.check))
                    stream.sendall(payload)
                    return receive(stream,self.check,self.initial['deadline'],
                        body_limit=65536,wire_limit=98304,cookies=True)
                if secure_context is not None:
                    with secure_context.wrap_socket(sock,server_hostname=parts.hostname) as secure:
                        response=send(secure)
                else:response=send(sock)
        self.check()
        self.jar.update(url,response['cookies'])
        return response

    def fetch(self):
        url=self.url;redirects=[];visited=set()
        for _ in range(4):
            if url in visited:raise ValueError('Portal HTTP redirect loop')
            visited.add(url)
            response=self.exchange(url)
            if response['status'] in (301,302,303,307,308):
                if not response['location']:raise ValueError('Missing portal redirect')
                target=capport.uri(urljoin(url,response['location']),legacy_http=True)
                if urlsplit(url).scheme=='https' and urlsplit(target).scheme!='https':
                    raise ValueError('Portal TLS downgrade')
                redirects.append(target);url=target
                continue
            if response['status']!=200:raise ValueError('Portal HTTP page rejected')
            page={'url':url,'redirects':redirects,'html':portal_form_fetch.html(response['body'],response['content_type'])}
            self.check()
            return page
        raise ValueError('Too many portal HTTP redirects')

    def submit(self,plan):
        if (not isinstance(plan,dict) or set(plan)!={'url','method','content_type','body','fingerprint'}
                or plan['content_type']!='application/x-www-form-urlencoded'
                or not re.fullmatch('[0-9a-f]{64}',plan['fingerprint'])
                or not isinstance(plan['body'],bytes) or len(plan['body'])>8192):
            raise ValueError('Invalid prepared portal action')
        method=plan['method'];url=plan['url'];body=plan['body']
        if method=='GET':
            if urlsplit(url).query:raise ValueError('Ambiguous prepared GET action')
            url+=('?' if body else '')+body.decode('ascii');body=b''
        response=self.exchange(url,method,body)
        # A redirect is a response to the action, not permission to replay a
        # POST or accept another agreement. Internet is checked independently.
        if response['status'] not in (200,204,302,303):raise ValueError('Portal action not accepted')
        self.check()
        return {'state':'SUBMITTED'}
