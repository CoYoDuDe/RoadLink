"""Read-only kernel checks used before a transport-mode handover."""
import json
from pathlib import Path

TABLES = ('51890', '51900', '51910', '51920', '51921', '51930')
PRIORITIES = ('21790', '21810', '21820', '21890', '21900', '21760')
TAGS = ('roadlink-ap-owned', 'roadlink-ap-route-owned', 'roadlink-vpn-owned',
        'roadlink-wan-bridge-owned', 'roadlink-direct-owned', 'roadlink-portal-client-owned')


def clear(command, namespace=Path('/run/netns/roadlink-wan')):
    if Path(namespace).exists():
        return False
    links = json.loads(command(['ip', '-j', 'link', 'show']).stdout)
    if any(item['ifname'] in ('aproadlink', 'wgroadlink', 'rlwanhost', 'rlwanpeer', 'disabledrlwan', 'disabledrlap',
                            'rlportalhost', 'rlportalpeer')
           for item in links):
        return False
    rules = command(['ip', 'rule', 'show']).stdout
    if any(priority + ':' in rules for priority in PRIORITIES):
        return False
    for table in TABLES:
        if command(['ip', 'route', 'show', 'table', table], check=False).stdout.strip():
            return False
    for tool in ('iptables-save', 'ip6tables-save'):
        if any(tag in command([tool]).stdout for tag in TAGS):
            return False
    return True
