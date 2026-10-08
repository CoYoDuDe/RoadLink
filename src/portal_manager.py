"""Daemon-side portal request scheduling; no network changes in DBus callbacks."""
from pathlib import Path
import subprocess
import sys
import time
import portal_api
import portal_known_api
import portal_live
import portal_request
import portal_session
import portal_session_runtime as runtime
import portal_state
import portal_pins
import portal_review
import portal_completion
from storage import load_json


class Manager:
    def __init__(self,service,owner,is_alive,itemtype=None):
        self.owner,self.alive=owner,is_alive
        self.worker=None
        self.completed=None
        self.api=portal_api.API(service,is_alive,self.busy,itemtype=itemtype)
        self.known_api=portal_known_api.API(service)

    def busy(self):
        return bool(self.worker and self.worker.poll() is None) or runtime.busy()

    def cancel(self):
        self.api.pending=None
        portal_request.revoke(self.owner)
        if runtime.ROOT.exists():
            runtime.private_root()
            (runtime.ROOT/'stop').touch()
        if self.worker and self.worker.poll() is None:
            try:self.worker.terminate()
            except ProcessLookupError:pass

    def view(self):
        evidence=load_json(runtime.WAN/'portal-result.json',{})
        if evidence.get('state') not in portal_state.CAPTIVE:return None
        try:return portal_live.system().inspect()
        except Exception:return None

    def form_status(self, view):
        if view is None: return ''
        try:
            session=load_json(runtime.ROOT/'session.json',{})
            portal_session.validate(session,*view,time.monotonic(),self.alive)
            portal_request.check(session,self.alive)
            if runtime.stopped() or not all(self.alive(load_json(runtime.ROOT/(name+'.json'),{}))
                                           for name in ('controller','guard')):
                return ''
            request=load_json(runtime.WAN/'portal-review-request.json',{})
            if portal_pins.request(session)!=request:return ''
            wan=view[1]
            result=portal_review.current(request,load_json(runtime.WAN/'portal-review-result.json',{}),
                wan['connection'],wan['lease'],wan['hints'],view[2],time.monotonic())
            return {'OBSERVED':'Formular erkannt; manuell anmelden',
                    'MANUAL_REQUIRED':'Seite im Browser pruefen',
                    'UNAVAILABLE':'Pruefung nicht moeglich; Browser nutzen'}.get((result or {}).get('state'),'Noch nicht geprueft')
        except (ValueError,RuntimeError,KeyError,TypeError,OSError):return ''

    def update(self,enabled=True):
        self.known_api.update()
        if self.worker and self.worker.poll() is not None:self.worker=None
        if not enabled:
            self.completed=None
            self.cancel()
            self.api.refresh(None,'STOPPING' if self.busy() else 'OFF')
            self.api.service['/Portal/FormStatus']=''
            return
        success=portal_completion.collect(self.owner,self.alive)
        if success:
            self.completed=success
            self.cancel()
        view=self.view()
        intent=self.api.take()
        if intent and intent['action']=='stop':
            self.completed=None
            self.cancel()
        elif intent and intent['action']=='start':
            self.completed=None
            try:
                if self.busy() or view is None:raise ValueError('Portal unavailable')
                session=intent['session']
                portal_session.validate(session,*view,time.monotonic(),self.alive)
                portal_request.publish(self.owner,session)
                self.worker=subprocess.Popen([sys.executable,str(Path(runtime.__file__)),'requested',session['id']],
                                             stdin=subprocess.DEVNULL)
            except Exception:
                portal_request.revoke(self.owner)
                self.api.service['/Portal/EditStatus']='Anmeldung nicht gestartet; erneut auswaehlen'
        status=load_json(runtime.ROOT/'status.json',{}).get('state','OFF')
        if self.worker and self.worker.poll() is None and status=='OFF':status='STARTING'
        if (self.completed and not self.busy() and status!='CLEANUP_FAILED'
                and 0<=time.monotonic()-self.completed['checked_at']<=30):
            status='COMPLETED'
        self.api.refresh(view,status)
        self.api.service['/Portal/FormStatus']=self.form_status(view)
