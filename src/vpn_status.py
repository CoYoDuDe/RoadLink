"""Fresh VPN Internet proof tied to one exact owned WLAN association and lease.

Neither a saved profile name nor READY from another connection is sufficient
for learning an open network or confirming a manually completed portal login.
"""
import copy
import math
from pathlib import Path
import time
from storage import load_json
import wan_lease

ROOT=Path('/run/roadlink-vpn')
WAN=Path('/run/roadlink-wan')
FILES={'binding':'connection','lease':'lease','state':'state','controller':'controller','guard':'guard','dhcp':'dhcp'}


def verified(status,binding,lease,owners,now):
    try:
        stamp=status['checked_at']
        expected=wan_lease.connection(binding['connection_id'],binding['profile_id'],binding['bssid'],binding)
        scalar={key:lease[key] for key in ('address','gateway')}
        if (expected!=binding or not wan_lease.current(lease,binding)
                or any(type(v) not in (int,float) or not math.isfinite(v) for v in (stamp,now))
                or not 0<=now-stamp<=30
                or status.get('state')!='READY' or status.get('internet') is not True
                or status.get('dns_ready') is not True or not status.get('dns')
                or status.get('wan')!='wifi' or status.get('wifi_profile_id')!=binding['profile_id']
                or status.get('wifi_connection')!=binding or status.get('wifi_lease')!=scalar
                or status.get('owner')!=owners[0] or status.get('guard')!=owners[1]):
            return None
        return {'connection':copy.deepcopy(binding),'lease':scalar,'checked_at':stamp,'dns':status['dns']}
    except (KeyError,TypeError,ValueError,IndexError):return None


def current_wifi(binding,lease,alive,root=ROOT,wan_root=WAN):
    root,wan_root=Path(root),Path(wan_root)
    def stopped():
        return any(folder.is_symlink() or any((folder/name).exists() for name in ('stop','cleaning'))
                   for folder in (root,wan_root))
    def owners():return [load_json(root/(name+'.json'),{}) for name in ('controller','guard')]
    def bundle():return {key:load_json(wan_root/(name+'.json'),{}) for key,name in FILES.items()}
    if stopped():return None
    before=bundle();vpn_owners=owners()
    if (before['binding']!=binding or before['lease']!=lease
            or not all(alive(owner) for owner in vpn_owners)
            or not wan_lease.owned(binding,before['dhcp'],before['controller'],before['guard'],before['state'],alive)):
        return None
    status=load_json(root/'status.json',{})
    result=verified(status,binding,lease,vpn_owners,time.monotonic())
    # Re-read owner generations after collecting proof, rejecting PID reuse,
    # DHCP replacement and re-association while evidence is being assembled.
    if (stopped() or bundle()!=before or owners()!=vpn_owners
            or not all(alive(owner) for owner in vpn_owners)
            or not wan_lease.owned(binding,before['dhcp'],before['controller'],before['guard'],before['state'],alive)):
        return None
    return result
