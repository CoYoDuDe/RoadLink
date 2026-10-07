"""Guard-owned veth uplink; deleting it invalidates any VPN WLAN route."""
import ipaddress
import json
from pathlib import Path
from storage import load_json, write_json
from wan_bridge import HOST, PEER, TAG, plan, rules, ipv6_rules


def command_for(family, action, item):
    table, chain, args = item
    return [family, '-w', '3', '-t', table, action, chain] + (['1'] if action == '-I' else []) + args


def configuration(vpn, command):
    values = json.loads(command(['ip', '-j', '-4', 'route', 'show', 'table', 'all']).stdout)
    networks = [ipaddress.IPv4Network(v['dst'], strict=False) for v in values if v.get('dst') not in (None, 'default')]
    for subnet in ('172.27.250.0/30', '10.250.250.0/30', '192.168.250.0/30'):
        if not any(ipaddress.IPv4Network(subnet).overlaps(n) for n in networks): break
    else: raise RuntimeError('No unused private WAN transit subnet')
    return plan(vpn['endpoint'], vpn['port'], subnet)


def start(root, state, bridge, command, inside):
    if any(Path('/sys/class/net/' + name).exists() for name in (HOST, PEER)):
        raise RuntimeError('WAN veth name already occupied')
    if Path('/proc/sys/net/ipv4/conf/all/rp_filter').read_text().strip() != '0':
        raise RuntimeError('Global strict reverse-path filtering requires additional WAN support')
    bridge = plan(bridge['endpoint'], int(bridge['port']), bridge['subnet'])
    state['bridge'] = bridge
    write_json(root / 'state.json', state)  # precedes all host mutations
    for family, builder in (('iptables', rules(bridge, 'host')), ('ip6tables', ipv6_rules('host'))):
        for item in builder: command(command_for(family, '-I', item))
    command(['ip', 'link', 'add', 'name', HOST, 'alias', TAG, 'type', 'veth', 'peer', 'name', PEER])
    # Some veth implementations ignore IFLA_IFALIAS during creation.
    # Keep the link down until its ownership tag is explicitly verified.
    command(['ip', 'link', 'set', HOST, 'alias', TAG])
    if Path('/sys/class/net/' + HOST + '/ifalias').read_text().strip() != TAG:
        raise RuntimeError('WAN veth ownership tag was not applied')
    command(['ip', 'link', 'set', PEER, 'netns', 'roadlink-wan'])
    Path('/proc/sys/net/ipv6/conf/' + HOST + '/disable_ipv6').write_text('1\n')
    Path('/proc/sys/net/ipv4/conf/' + HOST + '/rp_filter').write_text('0\n')
    inside(['sysctl', '-qw', 'net.ipv6.conf.' + PEER + '.disable_ipv6=1'])
    command(['ip', 'addr', 'add', bridge['host'] + '/30', 'dev', HOST])
    inside(['ip', 'addr', 'add', bridge['peer'] + '/30', 'dev', PEER])
    inside(['sysctl', '-qw', 'net.ipv4.ip_forward=1'])
    command(['ip', 'link', 'set', HOST, 'up'])
    inside(['ip', 'link', 'set', PEER, 'up'])
    return bridge


def cleanup(root, command):
    state = load_json(root / 'state.json', {})
    bridge = state.get('bridge')
    if not bridge: return
    device = Path('/sys/class/net/' + HOST)
    if device.exists():
        if (device / 'ifalias').read_text().strip() != TAG:
            raise RuntimeError('Foreign WAN veth; firewall retained')
        command(['ip', 'link', 'del', HOST])
    if device.exists(): raise RuntimeError('WAN veth removal failed')
    for family, builder in (('iptables', rules(bridge, 'host')), ('ip6tables', ipv6_rules('host'))):
        for item in reversed(list(builder)):
            command(command_for(family, '-D', item), check=False)
            if command(command_for(family, '-C', item), check=False).returncode == 0:
                raise RuntimeError('WAN host firewall cleanup incomplete')
