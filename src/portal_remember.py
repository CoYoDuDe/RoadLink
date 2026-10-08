"""Explicit GUI confirmation for one successfully completed static portal.

Candidate and session live only in daemon memory. Confirmation callbacks queue
an immutable token; disk writes and fresh transport checks happen in update.
"""
import copy
import math
import time
from urllib.parse import urlsplit
import portal_candidate
import portal_known
import portal_live
import portal_review
import portal_session
import vpn_status


class Stage:
    def __init__(self,service,alive,store=None,live=None,proof=None,clock=time.monotonic,itemtype=None):
        self.service,self.alive,self.clock=service,alive,clock
        self.store=portal_known.KnownPortals() if store is None else store
        self.live=live
        self.proof=proof
        self.session=self.candidate=self.completed=self.pending=None
        self.ready=False
        for name,value in {'Available':0,'ID':'','Summary':'','Status':''}.items():
            service.add_path('/Portal/Remember/'+name,value)
        options={'itemtype':itemtype} if itemtype else {}
        service.add_path('/Portal/Remember/Request','',writeable=True,onchangecallback=self.queue,**options)

    def clear(self):
        self.session=self.candidate=self.completed=self.pending=None
        self.ready=False
        for key,value in {'Available':0,'ID':'','Summary':'','Status':''}.items():
            self.service['/Portal/Remember/'+key]=value

    def capture(self,session,request,result,view):
        if self.completed:return
        try:
            portal_session.validate(session,*view,self.clock(),self.alive)
            wan=view[1]
            current=portal_review.current(request,result,wan['connection'],wan['lease'],wan['hints'],view[2],self.clock())
            candidate=current['candidate'] if current else None
            snapshot=portal_candidate.validate(candidate)
            if session['wan']['connection']['bssid'] not in snapshot['bssids']:
                raise ValueError('Candidate radio differs')
            self.session=copy.deepcopy(session)
            self.candidate=copy.deepcopy(candidate)
            self.observed_at=current['checked_at']
        except (ValueError,RuntimeError,KeyError,TypeError):
            # Do not retain an earlier form after an unsupported/changed page.
            self.session=self.candidate=None

    def complete(self,value):
        if (self.session and value['id']==self.session['id']
                and self.observed_at<=value['checked_at']<=self.observed_at+30):
            self.completed=copy.deepcopy(value)
        else:self.clear()

    def token(self):
        return portal_known.digest({'session':self.session['id'],'candidate':self.candidate['fingerprint']})[:24]

    def queue(self,path,value):
        if not self.ready or self.pending or value!='remember:'+self.token():return False
        self.pending=self.token()
        self.service['/Portal/Remember/Status']='Bestaetigung wird geprueft'
        return True

    def evidence(self):
        if not self.session or not self.completed or not self.candidate:raise ValueError('No completed candidate')
        live=portal_live.system() if self.live is None else self.live
        proof=(lambda binding,lease:vpn_status.current_wifi(binding,lease,self.alive)) if self.proof is None else self.proof
        view=live.inspect(require_page=False)
        portal_session.validate_connection(self.session,view[0],view[1],self.clock(),self.alive)
        value=proof(view[1]['connection'],view[1]['lease'])
        if (not value or value['connection']!=self.session['wan']['connection']
                or value['lease']!=self.session['wan']['lease']
                or type(value['checked_at']) not in (int,float) or not math.isfinite(value['checked_at'])
                or not self.completed['checked_at']<=value['checked_at']<=self.clock()
                or not 0<=self.clock()-value['checked_at']<=30):
            raise ValueError('Fresh completed WLAN Internet proof unavailable')
        after=live.inspect(require_page=False)
        portal_session.validate_connection(self.session,after[0],after[1],self.clock(),self.alive)
        if proof(after[1]['connection'],after[1]['lease'])!=value:
            raise ValueError('Internet proof changed during confirmation')
        return value

    def update(self):
        command,self.pending=self.pending,None
        self.ready=False
        try:
            value=self.evidence()
            self.ready=True
            if command:
                if command!=self.token():raise ValueError('Confirmation changed')
                token=command
                def check():
                    if token!=self.token():raise ValueError('Candidate changed while saving')
                    self.evidence()
                snapshot=portal_candidate.validate(self.candidate)
                proof={'fingerprint':self.candidate['fingerprint'],'manual_success':True,
                    'internet_proven':True,'checked_at':value['checked_at'],
                    'connection_id':self.session['wan']['connection']['connection_id'],
                    'bssid':self.session['wan']['connection']['bssid']}
                self.store.remember_snapshot(snapshot,proof,self.clock(),approved_free=True,
                    current_connection=proof['connection_id'],check=check)
                self.service['/Portal/Remember/Status']='Portal gespeichert'
                self.completed=None
                self.ready=False
        except (ValueError,RuntimeError,KeyError,TypeError,OSError):
            if command:self.service['/Portal/Remember/Status']='Nicht gespeichert; WLAN oder Internetnachweis hat sich geaendert'
        self.service['/Portal/Remember/Available']=int(self.ready)
        self.service['/Portal/Remember/ID']=self.token() if self.ready else ''
        self.service['/Portal/Remember/Summary']=(self.candidate['descriptor']['ssid']+' / '+
            urlsplit(self.candidate['descriptor']['url']).hostname) if self.ready else ''
