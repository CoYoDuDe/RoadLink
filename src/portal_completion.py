"""Read-only manual-session completion; never approves terms or learns a portal.

Only a session that actually reached LOGIN_READY can complete. Its selected
device and exact WLAN generation must still exist, and its independent VPN
DNS/TLS Internet probe must postdate that ready marker. Portal metadata is not
required after login; a disappearing page is not itself evidence of success.
"""
import math
from pathlib import Path
import time
import portal_live
import portal_request
import portal_session
import vpn_status
from storage import load_json


def collect(owner, alive, root=Path('/run/roadlink-portal'), live=None, proof=None,
            read=load_json, clock=time.monotonic):
    root=Path(root)
    if root.is_symlink(): return None
    try:
        session=read(root/'session.json',{})
        ready=read(root/'login-ready.json',{})
        controller=read(root/'controller.json',{})
        if (session.get('request_owner')!=owner or not alive(owner)
                or set(ready)!={'id','owner','ready_at'} or ready['id']!=session['id']
                or portal_session.identity(ready['owner'])!=controller):
            return None
        stamp=ready['ready_at']
        now=clock()
        if (type(stamp) not in (int,float) or not math.isfinite(stamp)
                or not session['started']<=stamp<=now<session['expires']):
            return None
        portal_request.check(session,alive)
        live=portal_live.system() if live is None else live
        proof=(lambda binding,lease:vpn_status.current_wifi(binding,lease,alive)) if proof is None else proof
        before=live.inspect(require_page=False)
        portal_session.validate_connection(session,before[0],before[1],clock(),alive)
        value=proof(before[1]['connection'],before[1]['lease'])
        if (not value or value['connection']!=session['wan']['connection']
                or value['lease']!=session['wan']['lease']
                or type(value['checked_at']) not in (int,float)
                or not math.isfinite(value['checked_at'])
                or not stamp<=value['checked_at']<=clock()
                or not 0<=clock()-value['checked_at']<=30):
            return None
        after=live.inspect(require_page=False)
        portal_session.validate_connection(session,after[0],after[1],clock(),alive)
        # Independent proof must survive re-reading all transport generations.
        if (proof(after[1]['connection'],after[1]['lease'])!=value
                or read(root/'session.json',{})!=session
                or read(root/'login-ready.json',{})!=ready
                or read(root/'controller.json',{})!=controller):
            return None
        portal_request.check(session,alive)
        return {'id':session['id'],'checked_at':value['checked_at']}
    except (ValueError,RuntimeError,KeyError,TypeError,OSError): return None
