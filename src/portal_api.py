"""Portal device selection and generation-bound intents for the daemon."""
import copy
import json
import re
import secrets
import time
import portal_clients
import portal_session
import portal_origins


class API:
    def __init__(self,service,is_alive,is_busy,clock=time.monotonic,itemtype=None):
        self.service,self.alive,self.busy,self.clock=service,is_alive,is_busy,clock
        self.view=None
        self.pending=None
        self.additional=[]
        self.extra_generation=None
        for path,value in {'Available':0,'Devices':'[]','SelectedDevice':'','URL':'',
                           'Status':'Keine WLAN-Anmeldung erforderlich','State':'OFF','EditStatus':''}.items():
            service.add_path('/Portal/'+path,value,writeable=path=='SelectedDevice',
                             **({'onchangecallback':self.choose} if path=='SelectedDevice' else {}))
        service.add_path('/Portal/AdditionalDomains','',writeable=True,onchangecallback=self.approve)
        options={'itemtype':itemtype} if itemtype else {}
        service.add_path('/Portal/Request','',writeable=True,onchangecallback=self.request,**options)

    def clear_approvals(self):
        self.additional=[]
        self.extra_generation=None
        self.service['/Portal/AdditionalDomains']=''

    def approve(self,path,value):
        try:
            if self.busy() or self.pending or self.view is None:raise ValueError()
            _,wan,result=self.view
            generation=portal_session.snapshot(wan,result,self.clock(),self.alive)
            additions=portal_origins.parse(value,generation['url'])
            self.additional=additions
            self.extra_generation=generation
            self.service['/Portal/EditStatus']='Zusatzdomains gelten nur fuer diese WLAN-Anmeldung'
            return True
        except (ValueError,TypeError,KeyError):
            self.service['/Portal/EditStatus']='Bis zu drei Domains, mit Komma trennen; nur vor dem Start'
            return False

    def choose(self,path,value):
        if not isinstance(value,str) or not re.fullmatch(r'[0-9a-f]{24}',value):return False
        try:
            if self.view is None:raise ValueError()
            portal_clients.select(value,self.view[0]['clients'])
            return True
        except ValueError:
            self.service['/Portal/EditStatus']='Geraet nicht mehr verfuegbar'
            return False

    def request(self,path,value):
        if value=='stop':
            self.clear_approvals()
            self.pending={'action':'stop'}
            self.service['/Portal/EditStatus']='Anmeldung wird beendet'
            return True
        if value!='start':return False
        try:
            if self.busy() or self.pending or self.view is None:raise ValueError()
            inventory,wan,result=self.view
            session=portal_session.create(secrets.token_hex(12),self.service['/Portal/SelectedDevice'],
                                          inventory,wan,result,self.clock(),self.alive,additional_urls=self.additional)
            self.pending={'action':'start','session':session}
            self.clear_approvals()
            self.service['/Portal/EditStatus']='Anmeldung angefordert'
            return True
        except (ValueError,KeyError,TypeError):
            self.service['/Portal/EditStatus']='Aktuelles Fahrzeuggeraet auswaehlen'
            return False

    def take(self):
        value=self.pending
        self.pending=None
        return value

    def refresh(self,view,state):
        self.view=copy.deepcopy(view) if view else None
        devices=[]
        url=''
        if self.view:
            try:
                inventory,wan,result=self.view
                if not all(self.alive(inventory[key]) for key in ('controller','guard')):
                    raise ValueError('Vehicle WLAN owners unavailable')
                authorized=portal_session.snapshot(wan,result,self.clock(),self.alive)
                devices=[{k:item.get(k,'') for k in ('id','name','ip')} for item in inventory['clients']]
                url=authorized['url']
            except (ValueError,KeyError,TypeError):self.view=None
        if self.view is None:devices=[];url=''
        if self.view is None or self.extra_generation != authorized:
            self.clear_approvals()
        service=self.service
        service['/Portal/Devices']=json.dumps(devices,ensure_ascii=False)
        service['/Portal/Available']=int(bool(url))
        service['/Portal/URL']=url
        if service['/Portal/SelectedDevice'] not in {item['id'] for item in devices}:
            service['/Portal/SelectedDevice']=''
        service['/Portal/State']=state
        service['/Portal/Status']={'OFF':'Fahrzeuggeraet fuer Anmeldung auswaehlen' if url else 'Keine WLAN-Anmeldung erforderlich',
            'WAITING_TARGETS':'Portal-Adressen werden geprueft','LOGIN_READY':'Anmeldeseite am ausgewaehlten Geraet oeffnen',
            'STARTING':'Anmeldung wird vorbereitet','STOPPING':'Anmeldung wird beendet',
            'CLEANUP_FAILED':'Aufraeumen fehlgeschlagen; Freigabe bleibt gesperrt'}.get(state,'Anmeldung wird vorbereitet')
