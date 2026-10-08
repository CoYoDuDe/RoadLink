"""Private, daemon-owned portal intent; never substitute a newer connection."""
import copy
from pathlib import Path
from storage import load_json,write_json

PATH=Path('/run/roadlink-portal-request.json')


def publish(owner,session):
    import portal_session
    portal_session.identity(owner)
    write_json(PATH,{'state':'REQUESTED','owner':dict(owner),'session':copy.deepcopy(session)})


def read(identifier,is_alive):
    value=load_json(PATH,{})
    session=value.get('session',{})
    if value.get('state')!='REQUESTED' or session.get('id')!=identifier or not is_alive(value.get('owner',{})):
        raise RuntimeError('Portal request revoked or daemon changed')
    return copy.deepcopy(value)


def check(session,is_alive):
    if 'request_owner' not in session:return
    value=read(session['id'],is_alive)
    expected={k:v for k,v in session.items() if k!='request_owner'}
    if value['owner']!=session['request_owner'] or value['session']!=expected:
        raise RuntimeError('Portal request changed')


def revoke(owner):
    value=load_json(PATH,{})
    if value.get('owner')==owner:
        write_json(PATH,{'state':'REVOKED','owner':dict(owner)})
