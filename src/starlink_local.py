"""Opt-in local Starlink access, restricted to the physical Ethernet port."""
import ipaddress
import json
import shlex
from storage import load_json, write_json, atomic_write

TABLE = '51922'
PRIORITY = '21809'
TAG = 'roadlink-starlink-local-owned'
TARGETS = {'192.168.100.1': '80,9200', '192.168.1.1': '80,9000'}
AP = 'aproadlink'
ETH = 'eth0'


def validate(value):
    if type(value) is not dict or set(value) != {'subnet', 'paths'} or type(value['paths']) is not dict:
        raise ValueError('Invalid local Starlink plan')
    subnet = ipaddress.IPv4Network(value['subnet'], strict=True)
    if subnet.prefixlen != 24 or not subnet.is_private or any(ipaddress.IPv4Address(ip) in subnet for ip in TARGETS):
        raise ValueError('Invalid vehicle subnet')
    paths = {}
    for target, path in value['paths'].items():
        if target not in TARGETS or type(path) is not dict or set(path) != {'gateway', 'source'}:
            raise ValueError('Invalid Starlink path')
        source = ipaddress.IPv4Address(path['source'])
        gateway = ipaddress.IPv4Address(path['gateway']) if path['gateway'] else None
        if source in subnet or source.is_unspecified or source.is_multicast or source.is_loopback:
            raise ValueError('Invalid Ethernet source')
        if gateway and (gateway in subnet or gateway.is_unspecified or gateway.is_multicast or gateway.is_loopback):
            raise ValueError('Invalid Ethernet gateway')
        paths[target] = {'gateway': str(gateway) if gateway else '', 'source': str(source)}
    return {'subnet': str(subnet), 'paths': paths}


def discover(subnet, command):
    paths = {}
    for target in TARGETS:
        result = command(['ip', '-j', '-4', 'route', 'get', target], check=False)
        if result.returncode:
            continue
        rows = json.loads(result.stdout or '[]')
        if (type(rows) is not list or len(rows) != 1 or type(rows[0]) is not dict):
            raise RuntimeError('Ambiguous Starlink Ethernet route')
        row = rows[0]
        if row.get('dev') != ETH or row.get('flags', []) or row.get('type', 'unicast') != 'unicast':
            continue
        paths[target] = {'gateway': row.get('gateway', ''), 'source': row.get('prefsrc', row.get('src', ''))}
    return validate({'subnet': subnet, 'paths': paths})


def rules(config):
    config = validate(config)
    tag = ['-m', 'comment', '--comment', TAG]
    for target in config['paths']:
        ports = TARGETS[target]
        yield ['filter', 'FORWARD', '-i', AP, '-o', ETH, '-s', config['subnet'], '-d', target+'/32',
               '-p', 'tcp', '-m', 'multiport', '--dports', ports, *tag, '-j', 'ACCEPT']
        yield ['filter', 'FORWARD', '-i', ETH, '-o', AP, '-s', target+'/32', '-d', config['subnet'],
               '-p', 'tcp', '-m', 'multiport', '--sports', ports,
               '-m', 'conntrack', '--ctstate', 'ESTABLISHED,RELATED', *tag, '-j', 'ACCEPT']
        yield ['nat', 'POSTROUTING', '-o', ETH, '-s', config['subnet'], '-d', target+'/32',
               '-p', 'tcp', '-m', 'multiport', '--dports', ports, *tag, '-j', 'MASQUERADE']


def rule_command(action, row):
    return ['iptables', '-w', '3', '-t', row[0], action, row[1]] + (['1'] if action=='-I' else []) + row[2:]


def route_command(action, target, path):
    result = ['ip', '-4', 'route', action, target+'/32']
    if path['gateway']:
        result += ['via', path['gateway']]
    return result + ['dev', ETH] + (['onlink'] if path['gateway'] else []) + ['table', TABLE]


def inventory(config, command):
    """Accept journaled subsets during crash cleanup, never foreign routes."""
    config = validate(config)
    result = command(['ip', '-j', '-4', 'route', 'show', 'table', TABLE], check=False)
    if result.returncode and 'FIB table does not exist' not in (result.stderr or ''):
        raise RuntimeError('Cannot inspect Starlink routes')
    rows = [] if result.returncode else json.loads(result.stdout or '[]')
    seen = set()
    for row in rows:
        if type(row) is not dict or set(row)-{'dst','type','metric','dev','gateway','flags','protocol','scope'}:
            raise RuntimeError('Foreign Starlink route retained')
        target = row.get('dst')
        if row.get('protocol','boot')!='boot':raise RuntimeError('Foreign Starlink route protocol')
        if target in seen:raise RuntimeError('Duplicate Starlink route')
        seen.add(target)
        if target=='default':
            if row.get('type')!='unreachable' or row.get('metric')!=32767 or 'dev' in row or 'gateway' in row:
                raise RuntimeError('Starlink fallback ownership changed')
        else:
            target = str(ipaddress.IPv4Network(target).network_address)
            if (row.get('dst') not in (target,target+'/32') or target not in config['paths']
                    or row.get('dev')!=ETH or row.get('gateway','')!=config['paths'][target]['gateway']
                    or row.get('type','unicast')!='unicast'
                    or row.get('flags',[]) not in ([],['onlink'],['linkdown'],['onlink','linkdown'])):
                raise RuntimeError('Foreign Starlink route retained')
    return rows


def selectors(command):
    rows = json.loads(command(['ip','-j','-4','rule','show']).stdout)
    selected = [row for row in rows if row.get('priority')==int(PRIORITY)]
    targets = set()
    for row in selected:
        if (set(row)-{'priority','src','dst','table','iif','iif_detached'} or row.get('src')!='all'
                or row.get('iif')!=AP or str(row.get('table'))!=TABLE):
            raise RuntimeError('Foreign Starlink selector retained')
        target = str(ipaddress.IPv4Network(row.get('dst','')).network_address)
        if row.get('dst') not in (target,target+'/32') or target not in TARGETS or target in targets:
            raise RuntimeError('Foreign Starlink selector retained')
        targets.add(target)
    return targets


def revoke(config, command):
    for row in reversed(list(rules(config))):
        while command(rule_command('-C',row),check=False).returncode==0:
            command(rule_command('-D',row))


def ensure_head(root, config, command):
    planned = [row for row in rules(config) if row[0]=='filter']
    if not planned:return
    def normalized(tokens):
        base={};rest=[];index=0
        while index<len(tokens):
            token=tokens[index]
            if token in ('-s','-d','-i','-o','-p'):
                if token in base or index+1>=len(tokens):raise RuntimeError('Ambiguous Starlink rule')
                index+=1;base[token]=tokens[index]
            elif tokens[index:index+2] in (['-m','tcp'],['-m','udp']):
                index+=1
            elif token=='--ctstate':
                index+=1;rest.extend([token,','.join(sorted(tokens[index].split(',')))])
            else:rest.append(token)
            index+=1
        return tuple(value for key in ('-s','-d','-i','-o','-p') if key in base for value in (key,base[key]))+tuple(rest)
    expected=[normalized(row[2:]) for row in reversed(planned)]
    def inspect():
        lines=command(['iptables','-w','3','-t','filter','-S','FORWARD']).stdout.splitlines()
        rows=[shlex.split(line)[2:] for line in lines if line.startswith('-A FORWARD ')]
        owned=[normalized(row) for row in rows if '--comment' in row and row[row.index('--comment')+1]==TAG]
        if sorted(owned)!=sorted(expected):raise RuntimeError('Starlink rule ownership changed')
        return [normalized(row) for row in rows[:len(expected)]]
    if inspect()==expected:return
    # Another owned runtime may have inserted a private-destination guard
    # above this explicit local exception. Move only our exact rules, atomically.
    lines=['*filter']
    lines+=['-D FORWARD '+shlex.join(row[2:]) for row in planned]
    lines+=['-I FORWARD 1 '+shlex.join(row[2:]) for row in planned]
    path=root/'starlink-local.restore'
    atomic_write(path,('\n'.join(lines+['COMMIT',''])).encode('ascii'))
    command(['iptables-restore','-w','3','--noflush',str(path)])
    if inspect()!=expected:raise RuntimeError('Starlink rule priority verification failed')
    path.unlink()


def refresh(root, command):
    old = validate(load_json(root/'starlink-local.json'))
    entries = inventory(old,command)
    if sum(row.get('dst')=='default' for row in entries)!=1:
        raise RuntimeError('Starlink unreachable fallback missing')
    if selectors(command)!=set(TARGETS):raise RuntimeError('Starlink selector changed')
    desired = discover(old['subnet'],command)
    if desired==old:
        if any(command(rule_command('-C',row),check=False).returncode for row in rules(old)):
            raise RuntimeError('Starlink firewall changed')
        ensure_head(root,old,command)
        return
    # Withdraw permissions first; keep both destination selectors and their
    # unreachable fallback throughout, including an Ethernet outage.
    revoke(old,command)
    for target,path in old['paths'].items():
        command(route_command('del',target,path),check=False)
    if any(row.get('dst')!='default' for row in inventory(old,command)):
        raise RuntimeError('Starlink old route cleanup failed')
    write_json(root/'starlink-local.json',desired)
    for target,path in desired['paths'].items():command(route_command('add',target,path))
    for row in rules(desired):command(rule_command('-I',row))
    ensure_head(root,desired,command)


def start(root, subnet, command):
    config = validate({'subnet':subnet,'paths':{}})
    if selectors(command) or inventory(config,command):raise RuntimeError('Starlink routing space occupied')
    write_json(root/'starlink-local.json',config)
    command(['ip','-4','route','add','unreachable','default','metric','32767','table',TABLE])
    for target in TARGETS:
        command(['ip','-4','rule','add','priority',PRIORITY,'iif',AP,'to',target+'/32','lookup',TABLE])
    refresh(root,command)


def cleanup(root, command):
    config = load_json(root/'starlink-local.json',None)
    if config is None:return []
    try:
        config = validate(config)
        revoke(config,command)
        rows = inventory(config,command); selected = selectors(command)
        for target in selected:
            command(['ip','-4','rule','del','priority',PRIORITY,'iif',AP,'to',target+'/32','lookup',TABLE])
        if selectors(command):raise RuntimeError('Starlink selector cleanup failed')
        for row in rows:
            if row['dst']=='default':
                command(['ip','-4','route','del','unreachable','default','metric','32767','table',TABLE])
            else:
                target=str(ipaddress.IPv4Network(row['dst']).network_address)
                command(route_command('del',target,config['paths'][target]))
        if inventory(config,command):raise RuntimeError('Starlink route cleanup failed')
        (root/'starlink-local.json').unlink()
        (root/'starlink-local.restore').unlink(missing_ok=True)
        return []
    except Exception:
        return ['Lokaler Starlink-Zugang konnte nicht vollstaendig bereinigt werden']
