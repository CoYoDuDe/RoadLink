"""Read-only live AP/WAN evidence for portal session authorization."""
import json
import os
from pathlib import Path
import subprocess
import time
import portal_clients
import portal_session
import wan_lease
from storage import load_json

FILES={'state':'state','connection':'connection','lease':'lease','hints':'portal-hints',
       'controller':'controller','guard':'guard','dhcp':'dhcp','result':'portal-result'}


class Live:
    def __init__(self, inventory, read, is_alive, namespace, query, stopping,
                 root=Path('/run/roadlink-wan')):
        self.inventory,self.read,self.alive=inventory,read,is_alive
        self.namespace,self.query,self.stopping=namespace,query,stopping
        self.root=Path(root)

    def bundle(self):
        return {key:self.read(self.root/(name+'.json'),{}) for key,name in FILES.items()}

    def inspect(self):
        if self.stopping(): raise RuntimeError('Portal transport is stopping')
        bundle=self.bundle()
        state=bundle['state']
        expected=(state.get('namespace_inode'),state.get('namespace_device'))
        if self.namespace()!=expected: raise RuntimeError('Portal WAN namespace changed')
        if not wan_lease.owned(bundle['connection'],bundle['dhcp'],bundle['controller'],
                               bundle['guard'],state,self.alive):
            raise RuntimeError('Portal WAN processes changed')
        links=self.query('links')
        if (len(links)!=1 or links[0].get('ifname')!='disabledrlwan'
                or links[0].get('ifindex')!=state.get('ifindex')):
            raise RuntimeError('Portal WAN radio changed')
        raw=self.query('association')
        fields={}
        if not isinstance(raw,str) or len(raw)>16384: raise RuntimeError('Invalid WLAN association response')
        for line in raw.splitlines():
            if '=' not in line: continue
            key,value=line.split('=',1)
            if key in fields: raise RuntimeError('Ambiguous WLAN association response')
            fields[key]=value
        if fields.get('wpa_state')!='COMPLETED' or fields.get('bssid','').lower()!=bundle['connection']['bssid']:
            raise RuntimeError('Portal WLAN association changed')
        inventory=self.inventory()
        after=self.bundle()
        if (self.stopping() or self.namespace()!=expected
                or {k:v for k,v in after.items() if k!='result'}!={k:v for k,v in bundle.items() if k!='result'}
                or self.query('links')!=links):
            raise RuntimeError('Portal transport changed during evidence collection')
        now=time.monotonic()
        if portal_session.snapshot(bundle,bundle['result'],now,self.alive)!=portal_session.snapshot(after,after['result'],now,self.alive):
            raise RuntimeError('Portal login page changed during evidence collection')
        return inventory,after,after['result']

    def check(self, session):
        inventory,wan,result=self.inspect()
        return portal_session.validate(session,inventory,wan,result,time.monotonic(),self.alive)


def system():
    from ap_runtime import alive
    root=Path('/run/roadlink-wan')
    handle=Path('/run/netns/roadlink-wan')
    def namespace():
        if handle.is_symlink(): raise RuntimeError('Unsafe portal namespace handle')
        value=handle.stat()
        host=os.stat('/proc/self/ns/net')
        if (value.st_ino,value.st_dev)==(host.st_ino,host.st_dev):
            raise RuntimeError('Portal WAN shares host network')
        return value.st_ino,value.st_dev
    def query(kind):
        args=(['ip','-j','link','show','dev','disabledrlwan'] if kind=='links' else
              ['wpa_cli','-p',str(root/'control'),'-i','disabledrlwan','status'])
        result=subprocess.run(['ip','netns','exec','roadlink-wan',*args],check=True,
                              capture_output=True,text=True,timeout=3)
        return json.loads(result.stdout) if kind=='links' else result.stdout
    def stopping():
        return any((Path('/run/roadlink-'+name)/marker).exists()
                   for name in ('ap','wan') for marker in ('stop','cleaning'))
    return Live(portal_clients.available,load_json,alive,namespace,query,stopping)
