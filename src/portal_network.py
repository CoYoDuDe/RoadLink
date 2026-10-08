"""Journalled portal network lifecycle; callers provide guarded executors.

host/wan execute argv only in their verified namespaces. check validates the
live portal session before mutations; namespace returns the current WAN inode
and device. Cleanup revokes allowances before inspecting/removing owned links.
"""
import ipaddress
import json
from pathlib import Path
import secrets
import portal_router as router
from storage import load_json, write_json


def rule_command(family, action, item):
    table, chain, args = item
    return [family,'-w','1','-t',table,action,chain]+(['1'] if action=='-I' else [])+args


def linked(left, right):
    # iproute2 emits the peer's name for same-namespace veths on Venus;
    # newer versions may emit link_index. Require the exact reciprocal pair.
    if 'link_index' in left:
        return type(left['link_index']) is int and left['link_index']==right['ifindex']
    return left.get('link')==right['ifname']


class Network:
    def __init__(self, root, host, wan, check, namespace):
        self.root, self.host, self.wan = Path(root), host, wan
        self.check, self.namespace = check, namespace
        self.path = self.root/'network.json'

    def links(self, scope):
        execute = self.host if scope=='host' else self.wan
        return json.loads(execute(['ip','-j','-d','link','show']).stdout or '[]')

    def save(self, state):
        write_json(self.path,state)

    def mutate(self, scope, args):
        self.check()
        state = load_json(self.path,{})
        if tuple(state['namespace']) != tuple(self.namespace()): raise RuntimeError('Portal WAN namespace changed')
        result = (self.host if scope=='host' else self.wan)(args)
        self.check()
        return result

    def start(self, config):
        self.check()
        config = router.canonical(config)
        if load_json(self.path,{}): raise RuntimeError('Previous portal network not drained')
        links = self.links('host')+self.links('wan')
        if any(value['ifname'] in (router.HOST,router.PEER) for value in links):
            raise RuntimeError('Portal transit interface occupied')
        if (self.host(['ip','route','show','table',router.TABLE],check=False).stdout.strip()
                or router.PRIORITY+':' in self.host(['ip','rule','show']).stdout):
            raise RuntimeError('Portal policy table or priority occupied')
        for scope,execute in (('host',self.host),('wan',self.wan)):
            for family in ('iptables','ip6tables'):
                if router.TAG in execute([family+'-save']).stdout:
                    raise RuntimeError('Existing portal firewall ownership')
            routes = json.loads(execute(['ip','-j','-4','route','show','table','all']).stdout or '[]')
            for route in routes:
                if route.get('dst') not in (None,'default') and ipaddress.IPv4Network(config['transit']).overlaps(
                        ipaddress.IPv4Network(route['dst'],strict=False)):
                    raise RuntimeError('Portal transit subnet already routed')
        temporary = 'rlps'+secrets.token_hex(5)
        if any(value['ifname']==temporary for value in links): raise RuntimeError('Temporary portal interface occupied')
        state = {'config':config,'namespace':list(self.namespace()),'temporary':temporary,
                 'host_index':None,'peer_index':None,'host_rules':False,'wan_rules':False,'routes':False}
        self.save(state)
        # Guards can remove all regenerated rules after any partially executed
        # phase. Existing identical tagged rules were rejected before journal.
        for scope in ('host','wan'):
            state[scope+'_rules']=True; self.save(state)
            for family,items in (('iptables',router.rules(config,scope)),('ip6tables',router.ipv6_rules(scope))):
                for item in items: self.mutate(scope,rule_command(family,'-I',item))
        self.mutate('host',['ip','link','add',router.HOST,'type','veth','peer','name',temporary])
        host = next(value for value in self.links('host') if value['ifname']==router.HOST)
        peer = next(value for value in self.links('host') if value['ifname']==temporary)
        state.update(host_index=host['ifindex'],peer_index=peer['ifindex']); self.save(state)
        for name in (router.HOST,temporary):
            self.mutate('host',['ip','link','set',name,'alias',router.TAG])
        if any(value.get('ifalias')!=router.TAG for value in self.links('host') if value['ifname'] in (router.HOST,temporary)):
            raise RuntimeError('Portal interface ownership tag unavailable')
        state['tag_required']=True; self.save(state)
        self.mutate('host',['ip','link','set',temporary,'name',router.PEER])
        # Executor knows its captured namespace name; moving by name is scoped
        # by check and the same inode/device validated before and after command.
        self.mutate('host',['ip','link','set',router.PEER,'netns',self.wan.namespace_name])
        moved = next(value for value in self.links('wan') if value['ifname']==router.PEER)
        if moved['ifindex']!=state['peer_index'] or moved.get('ifalias')!=router.TAG:
            raise RuntimeError('Portal peer identity changed while moving')
        for scope,device,address in (('host',router.HOST,config['host']),('wan',router.PEER,config['peer'])):
            self.mutate(scope,['sysctl','-qw','net.ipv6.conf.'+device+'.disable_ipv6=1'])
            self.mutate(scope,['sysctl','-qw','net.ipv4.conf.'+device+'.rp_filter=0'])
            self.mutate(scope,['ip','addr','add',address+'/30','dev',device])
        # Existing guarded AP/WAN runtimes own forwarding sysctls. This class
        # never changes global forwarding or the native default route.
        # Linux rejects gateway routes on a down veth. Drops and exact target
        # allowances are already installed; no client policy selector exists
        # until the unreachable fallback and every target route are present.
        self.mutate('host',['ip','link','set',router.HOST,'up'])
        self.mutate('wan',['ip','link','set',router.PEER,'up'])
        state['routes']=True; self.save(state)
        for args in router.routes(config): self.mutate('host',args)
        return state

    def remove_rule(self, scope, family, item):
        execute = self.host if scope=='host' else self.wan
        # Each planned rule is inserted once after exclusive tag preflight.
        # Delete its exact specification directly; final save verification
        # catches failed removals/duplicates without launching two extra
        # Python command children per rule. Never flush a chain or tag group.
        execute(rule_command(family,'-D',item),check=False)

    def cleanup(self):
        state = load_json(self.path,{})
        if not state: return
        config = router.canonical(state['config'])
        # A vanished/replaced WAN handle must not prevent root-side revocation.
        # Never execute cleanup commands in an unverified replacement namespace.
        try:
            same_namespace = tuple(state['namespace'])==tuple(self.namespace())
        except (OSError, RuntimeError):
            same_namespace = False
        # Revoke every allowance/NAT/mark first, even if a foreign replacement
        # prevents link deletion. Retained drops keep the selected client safe.
        for scope in ('host','wan'):
            if not state[scope+'_rules'] or scope=='wan' and not same_namespace: continue
            for item in reversed(list(router.rules(config,scope))):
                if item[2][-1]!='DROP': self.remove_rule(scope,'iptables',item)
        host_links = self.links('host')
        host = next((value for value in host_links if value['ifname']==router.HOST),None)
        if host:
            if state['host_index'] is None or host.get('ifalias','')=='' and not state.get('tag_required',False):
                # Crash between add and index journal: only an exact reciprocal
                # down veth pair with the pre-journalled random peer is adopted.
                peer = next((value for value in host_links if value['ifname']==state['temporary']),None)
                if (not peer or any(value.get('linkinfo',{}).get('info_kind')!='veth' or 'UP' in value.get('flags',[])
                                    or value.get('ifalias','') for value in (host,peer))
                        or not linked(host,peer) or not linked(peer,host)):
                    raise RuntimeError('Unknown partial portal pair retained')
                if state['host_index'] is not None and (host['ifindex']!=state['host_index'] or peer['ifindex']!=state['peer_index']):
                    raise RuntimeError('Foreign partial portal pair retained')
            elif host['ifindex']!=state['host_index'] or host.get('ifalias')!=router.TAG:
                raise RuntimeError('Foreign portal interface retained after revocation')
            self.host(['ip','link','del',router.HOST])
        if any(value['ifname']==router.HOST for value in self.links('host')):
            raise RuntimeError('Portal link deletion incomplete')
        if state['routes']:
            selector = list(router.routes(config))[-1]
            selector[2]='del'
            self.host(selector,check=False)
            # Link deletion removes its unicast routes. Delete only our exact
            # unreachable default; any foreign rows keep cleanup incomplete.
            self.host(['ip','route','del','unreachable','default','metric','32767','table',router.TABLE],check=False)
            if (self.host(['ip','route','show','table',router.TABLE],check=False).stdout.strip()
                    or router.PRIORITY+':' in self.host(['ip','rule','show']).stdout):
                raise RuntimeError('Portal policy cleanup incomplete; unknown rows retained')
        for scope in ('host','wan'):
            if not state[scope+'_rules'] or scope=='wan' and not same_namespace: continue
            for family,items in (('iptables',router.rules(config,scope)),('ip6tables',router.ipv6_rules(scope))):
                for item in reversed(list(items)):
                    if item[2][-1]=='DROP':self.remove_rule(scope,family,item)
                execute=self.host if scope=='host' else self.wan
                if router.TAG in execute([family+'-save']).stdout:
                    raise RuntimeError('Portal firewall cleanup incomplete; journal retained')
        self.save({})
