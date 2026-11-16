"""Strict allowlist of read-only host commands.

Tracked "child" wrappers exist so a dying controller never leaves an
untracked state-changing process behind. Pure reads cannot leave state, so
they may run directly and skip a full Python interpreter start (on a Pi 4
this was ~15 interpreter starts per second, about one CPU core).
Anything not matched exactly here keeps using the tracked wrapper.
"""
import re

_IP_OPTS = {'-j', '-4', '-6', '-d', '-s', '-o', '-br', '-details', '-json', '-brief'}
_IP_OBJECTS = {'route', 'rule', 'link', 'addr', 'address', 'neigh', 'netconf'}
_IP_VERBS = {'show', 'list', 'get', 'ls'}
_IPT_READ = {'-C', '--check', '-S', '--list-rules', '-L', '--list'}
_IPT_WRITE = {'-A', '--append', '-I', '--insert', '-D', '--delete', '-R', '--replace',
              '-N', '--new-chain', '-X', '--delete-chain', '-F', '--flush', '-Z', '--zero',
              '-P', '--policy', '-E', '--rename-chain'}
_HOSTAPD_READ = {'status', 'all_sta', 'get_config', 'ping'}
_NAME = re.compile(r'[A-Za-z0-9_.:-]{1,32}')


def is_readonly(args):
    if not isinstance(args, (list, tuple)) or not args or not all(isinstance(a, str) for a in args):
        return False
    args = list(args)
    tool = args[0]
    if tool == 'ip':
        rest = args[1:]
        while rest and rest[0] in _IP_OPTS:
            rest = rest[1:]
        if rest[:2] == ['netns', 'list']:
            return len(rest) == 2
        if rest[:2] == ['netns', 'exec']:
            return len(rest) > 3 and bool(_NAME.fullmatch(rest[2])) and is_readonly(rest[3:])
        return len(rest) >= 2 and rest[0] in _IP_OBJECTS and rest[1] in _IP_VERBS
    if tool == 'wg':
        return len(args) >= 2 and args[1] == 'show'
    if tool in ('iptables', 'ip6tables'):
        flags = set(args[1:])
        return bool(flags & _IPT_READ) and not flags & _IPT_WRITE
    if tool == 'hostapd_cli':
        return len(args) >= 2 and args[-1] in _HOSTAPD_READ
    if tool == 'iw':
        if args[1:] in (['reg', 'get'],):
            return True
        if len(args) >= 4 and args[1] == 'dev' and _NAME.fullmatch(args[2]):
            return args[3:] in (['link'], ['info'], ['station', 'dump'], ['get', 'power_save'])
        if len(args) == 4 and args[1] == 'phy' and _NAME.fullmatch(args[2]):
            return args[3] == 'info'
        return False
    return False
