"""Select one ready portal session for DHCP options; this grants no forwarding."""
from pathlib import Path
import portal_session
import portal_router
import portal_request

AP=Path('/run/roadlink-ap')
PORTAL=Path('/run/roadlink-portal')
WAN=Path('/run/roadlink-wan')


def selected(subnet,read,is_alive,now,stopping):
    try:
        if stopping():return None
        session=read(PORTAL/'session.json',{})
        if read(PORTAL/'status.json',{}).get('state')!='LOGIN_READY':return None
        if not all(is_alive(read(root/(name+'.json'),{}))
                   for root in (AP,PORTAL) for name in ('controller','guard')):return None
        actual={'controller':read(AP/'controller.json',{}),'guard':read(AP/'guard.json',{}),
                'ifindex':read(AP/'radio.json',{}).get('ap_ifindex'),'subnet':subnet}
        if portal_session.ap_generation(actual)!=session['ap']:return None
        portal_request.check(session,is_alive)
        names={'state':'state','connection':'connection','lease':'lease','hints':'portal-hints',
               'controller':'controller','guard':'guard','dhcp':'dhcp'}
        wan={key:read(WAN/(name+'.json'),{}) for key,name in names.items()}
        binding=wan['connection']
        if portal_session.snapshot(wan,read(WAN/'portal-result.json',{}),now,is_alive)!=session['wan']:return None
        approved=portal_session.pin_set(session,read(WAN/'portal-pins.json',{}),now)
        lease=session['wan']['lease']
        config=portal_router.plan(subnet,session['device'],lease,approved['endpoints'],lease['gateway'])
        network=read(PORTAL/'network.json',{})
        if (network.get('config')!=config or not network.get('routes') or not network.get('tag_required')
                or network.get('namespace')!=[binding['namespace_inode'],binding['namespace_device']]):return None
        if stopping():return None
        return {key:session['device'][key] for key in ('ip','mac')}
    except (ValueError,KeyError,TypeError,OSError,RuntimeError):return None
