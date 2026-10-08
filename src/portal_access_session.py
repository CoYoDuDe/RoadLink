"""Coordinate one authorized portal session; caller owns guard and runtime lock.

check validates the complete live session. read_pins reads the WAN worker's
bound response. request submits its bound request. Network executors and broker
are supplied by the guarded runtime; this module never launches processes.
"""
import ipaddress
import copy
import time
import portal_pins
import portal_router
import portal_session


class Access:
    def __init__(self, session, check, read_pins, request, network, broker_factory):
        self.session=copy.deepcopy(session)
        self.check,self.read_pins,self.request=check,read_pins,request
        self.network,self.broker_factory=network,broker_factory
        self.broker=None
        self.config=None
        self.installing=None
        self.network.check=self.network_check

    def network_check(self):
        self.check()
        expected=self.installing or self.config
        if expected is not None:
            approved=portal_session.pin_set(self.session,self.read_pins(),time.monotonic())
            if self.configuration(approved)!=expected:
                raise RuntimeError('Portal targets changed during network installation')
        self.check()

    def close(self):
        if self.broker is not None:
            self.broker.close()
            self.broker=None
        self.config=None
        self.installing=None
        self.network.cleanup()

    def pins(self):
        self.check()
        value=portal_session.pin_set(self.session,self.read_pins(),time.monotonic())
        self.check()
        if self.config is None or self.configuration(value)!=self.config:
            raise RuntimeError('Portal target set changed')
        return value['dns']

    def configuration(self, approved):
        lease=self.session['wan']['lease']
        return portal_router.plan(self.session['ap']['subnet'],self.session['device'],lease,
                                  approved['endpoints'],lease['gateway'])

    def step(self):
        try:
            self.check()
            self.request(portal_pins.request(self.session))
            self.check()
            try:
                approved=portal_session.pin_set(self.session,self.read_pins(),time.monotonic())
            except ValueError:
                # Waiting for fresh bound pins never leaves an old allowance.
                self.close()
                self.check()
                return 'WAITING_TARGETS'
            config=self.configuration(approved)
            self.check()
            if config!=self.config:
                self.close()
                self.check()
                self.installing=config
                self.network.start(config)
                self.config=config
                self.installing=None
                gateway=str(ipaddress.IPv4Network(config['subnet'])[1])
                self.broker=self.broker_factory(gateway,config['client'],portal_router.AP,
                                               self.check,self.pins)
            self.check()
            self.broker.poll()
            self.check()
            return 'LOGIN_READY'
        except BaseException:
            self.close()
            raise
