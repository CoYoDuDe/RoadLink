"""Journaled direct-route ownership. A separate process guard performs cleanup."""
from pathlib import Path
import json
import direct_router as routing
from storage import load_json, write_json


def forwarding():
    return Path('/proc/sys/net/ipv4/ip_forward').read_text().strip()


def covered(command):
    if not Path('/sys/class/net/aproadlink').exists():
        return True
    # The AP guard removes its interface before removing these base drops.
    for tool in ('iptables', 'ip6tables'):
        for direction in ('-i', '-o'):
            if command([tool, '-w', '3', '-C', 'FORWARD', direction, routing.AP,
                        '-m', 'comment', '--comment', 'roadlink-ap-owned', '-j', 'DROP'],
                       check=False).returncode:
                return False
    return True


class Policy:
    def __init__(self, root, command):
        self.root, self.command = Path(root), command

    def state(self):
        return load_json(self.root / 'policy.json', {})

    def journal(self, state):
        write_json(self.root / 'policy.json', state)

    def start(self):
        for table in (routing.TABLE, routing.AP_TABLE):
            if self.command(['ip', 'route', 'show', 'table', table], check=False).stdout.strip():
                raise RuntimeError('Direct policy table occupied')
        rules = self.command(['ip', 'rule', 'show']).stdout
        if any(priority + ':' in rules for priority in (routing.AP_PRIORITY, routing.PROBE_PRIORITY)):
            raise RuntimeError('Direct policy priority occupied')
        state = {'forward_before': forwarding(),
                 'configs': [], 'started': True}
        self.journal(state)  # precedes every possible route/rule mutation
        for table in (routing.TABLE, routing.AP_TABLE):
            self.command(['ip', 'route', 'add', 'unreachable', 'default', 'metric', '32767', 'table', table])
        self.command(['ip', 'rule', 'add', 'priority', routing.PROBE_PRIORITY, 'fwmark',
                      routing.MARK + '/0xffffffff', 'lookup', routing.TABLE])
        self.command(['ip', 'rule', 'add', 'priority', routing.AP_PRIORITY, 'iif',
                      routing.AP, 'lookup', routing.AP_TABLE])

    def route(self, table, config=None):
        if table not in (routing.TABLE, routing.AP_TABLE):
            raise ValueError('Refusing a route outside owned direct tables')
        entries = self.owned_routes(table)
        state = self.state()
        recorded = state.setdefault('routes', {}).get(table, [])
        if config is None:
            for entry in entries:
                if entry.get('metric') == 10:
                    args = ['ip', 'route', 'del', 'default', 'metric', '10', 'table', table,
                            'dev', entry['dev'], 'src', entry['prefsrc']]
                    if entry.get('gateway'):
                        args += ['via', entry['gateway']]
                    self.command(args, check=False)
            if any(entry.get('metric') == 10 for entry in self.owned_routes(table)):
                raise RuntimeError('Direct route removal incomplete')
            state['routes'][table] = []
            self.journal(state)
            return
        config = routing.plan(config['subnet'], config, config['dns'])
        state['routes'][table] = recorded + ([config] if config not in recorded else [])
        self.journal(state)  # guard accepts old or new route after interrupted replacement
        args = ['ip', 'route', 'replace', 'default', 'table', table, 'metric', '10',
                'dev', config['dev'], 'src', config['source']]
        if config['gateway']:
            args += ['via', config['gateway'], 'onlink']
        self.command(args)
        self.owned_routes(table)
        state['routes'][table] = [config]
        self.journal(state)

    def owned_routes(self, table):
        result = self.command(['ip', '-j', 'route', 'show', 'table', table], check=False)
        entries = json.loads(result.stdout or '[]')
        recorded = self.state().get('routes', {}).get(table, [])
        for entry in entries:
            if (entry.get('dst') == 'default' and entry.get('type') == 'unreachable'
                    and entry.get('metric') == 32767):
                continue
            matches = (entry.get('dst') == 'default' and entry.get('metric') == 10
                       and entry.get('type', 'unicast') == 'unicast'
                       and any(entry.get('dev') == config['dev']
                               and entry.get('prefsrc') == config['source']
                               and entry.get('gateway', '') == config['gateway']
                               for config in recorded))
            if not matches:
                raise RuntimeError('Direct table changed externally; foreign route retained')
        return entries

    def verify(self, active=None):
        for table in (routing.TABLE, routing.AP_TABLE):
            entries = self.owned_routes(table)
            if sum(entry.get('type') == 'unreachable' and entry.get('dst') == 'default'
                   and entry.get('metric') == 32767 for entry in entries) != 1:
                raise RuntimeError('Direct unreachable fallback changed externally')
            if table == routing.AP_TABLE:
                selected = [entry for entry in entries if entry.get('metric') == 10]
                if (not active and selected or active and (len(selected) != 1
                        or selected[0].get('dev') != active['dev']
                        or selected[0].get('prefsrc') != active['source']
                        or selected[0].get('gateway', '') != active['gateway'])):
                    raise RuntimeError('Direct active route changed externally')

    def block(self):
        # The unreachable route stays installed, even during partial cleanup.
        error = None
        try:
            self.route(routing.AP_TABLE)
        except Exception as exc:
            error = exc  # still revoke our permits if a foreign route prevents removal
        state = self.state()
        for config in state.get('configs', []):
            for rule in reversed(list(routing.rules(config))):
                self.command(routing.rule_command('-D', rule), check=False)
                if not self.command(routing.rule_command('-C', rule), check=False).returncode:
                    raise RuntimeError('Direct permissions could not be removed')
        state['configs'] = []
        self.journal(state)
        if error:
            raise error

    def activate(self, config):
        config = routing.plan(config['subnet'], config, config['dns'])
        self.block()
        if not covered(self.command):
            raise RuntimeError('AP base firewall is unavailable')
        state = self.state()
        state['configs'] = [config]
        self.journal(state)  # records even an interrupted partial ruleset
        for rule in routing.rules(config):
            self.command(routing.rule_command('-I', rule))
        self.command(['sysctl', '-qw', 'net.ipv4.ip_forward=1'])
        self.route(routing.AP_TABLE, config)  # only after all filtering is ready

    def cleanup(self):
        state = self.state()
        if not state:
            return
        self.block()
        self.route(routing.TABLE)
        if not covered(self.command):
            raise RuntimeError('AP firewall changed; retaining unreachable policy')
        for args in (['priority', routing.AP_PRIORITY, 'iif', routing.AP, 'lookup', routing.AP_TABLE],
                     ['priority', routing.PROBE_PRIORITY, 'fwmark', routing.MARK + '/0xffffffff', 'lookup', routing.TABLE]):
            self.command(['ip', 'rule', 'del'] + args, check=False)
        for table in (routing.TABLE, routing.AP_TABLE):
            self.command(['ip', 'route', 'del', 'unreachable', 'default', 'metric', '32767', 'table', table], check=False)
            if self.command(['ip', 'route', 'show', 'table', table], check=False).stdout.strip():
                raise RuntimeError('Direct table cleanup incomplete')
        rules = self.command(['ip', 'rule', 'show']).stdout
        if any(priority + ':' in rules for priority in (routing.AP_PRIORITY, routing.PROBE_PRIORITY)):
            raise RuntimeError('Direct policy cleanup incomplete')
        if state['forward_before'] == '0':
            self.command(['sysctl', '-qw', 'net.ipv4.ip_forward=0'])
