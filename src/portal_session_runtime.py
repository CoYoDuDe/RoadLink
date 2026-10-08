#!/usr/bin/env python3
"""Selected-device portal runtime, with an independent owner-token watchdog.

Daemon requests retain the selected AP/WAN generation and absolute expiry.
"""
import json
import os
from pathlib import Path
import secrets
import signal
import stat
import subprocess
import sys
import time
from storage import atomic_write,load_json,write_json

ROOT=Path('/run/roadlink-portal')
WAN=Path('/run/roadlink-wan')
NS='roadlink-wan'


def identity():
    return {'pid':os.getpid(),'start':token(os.getpid())}


def token(pid):
    try:
        fields=Path('/proc/{}/stat'.format(int(pid))).read_text().rsplit(')',1)[1].split()
        return None if fields[0]=='Z' else fields[19]
    except (OSError,ValueError,TypeError,IndexError):return None


def alive(owner):
    return bool(owner and type(owner.get('pid')) is int and owner['pid']>0
                and owner.get('start') and token(owner['pid'])==owner['start'])


def private_root():
    info=ROOT.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:
        raise RuntimeError('Unsafe portal runtime directory')


def fd_namespace(fd,session):
    info=os.fstat(fd)
    binding=session['wan']['connection']
    expected=(binding['namespace_inode'],binding['namespace_device'])
    if (info.st_ino,info.st_dev)!=expected: raise RuntimeError('Portal namespace descriptor changed')
    return expected


def stopped(): return any((ROOT/name).exists() for name in ('stop','cleaning'))


def busy():
    from runtime_lock import busy as locked
    if locked(ROOT): return True
    if not ROOT.exists(): return False
    private_root()
    if any(alive(load_json(ROOT/(name+'.json'),{})) for name in ('controller','guard','mutation')):
        return True
    if load_json(ROOT/'network.json',{}): return True
    return bool(load_json(ROOT/'session.json',{})) and load_json(ROOT/'result.json',{}).get('cleaned') is not True


def stop():
    deadline=time.monotonic()+30
    signalled=None
    while time.monotonic()<deadline:
        if ROOT.exists():
            private_root()
            (ROOT/'stop').touch()
            controller=load_json(ROOT/'controller.json',{})
            if controller!=signalled and alive(controller):
                try:os.kill(controller['pid'],signal.SIGTERM)
                except ProcessLookupError:pass
                signalled=controller
        if not busy():return
        time.sleep(.1)
    raise RuntimeError('Portal session cleanup incomplete')


def pulse(): atomic_write(ROOT/'heartbeat',str(time.monotonic()).encode())


def child(parent,lock_fd,ns_fd,args,tracked):
    private_root()
    session=load_json(ROOT/'session.json',{})
    owner=identity()
    # Registration precedes authorization and exec. The inherited flock keeps
    # late children from racing reuse even before they publish their identity.
    write_json(ROOT/'mutation.json',owner)
    if not alive(parent): raise RuntimeError('Portal command parent exited')
    if tracked:
        import portal_request
        import portal_live
        portal_request.check(session,alive)
        if (stopped() or load_json(ROOT/'controller.json',{})!=parent
                or not alive(load_json(ROOT/'guard.json',{}))):
            raise RuntimeError('Portal command no longer authorized')
        portal_live.system().check(session)
    if ns_fd>=0:
        fd_namespace(ns_fd,session)
        os.setns(ns_fd,0)
        os.set_inheritable(ns_fd,False)
    os.set_inheritable(lock_fd,False)
    if not alive(parent) or tracked and stopped(): raise RuntimeError('Portal command stopped before exec')
    os.execvp(args[0],args)


def executors(lock_fd,ns_fd,session,tracked,check):
    parent=identity()
    def execute(scope,args,check_command=True):
        if tracked: check()
        command=[sys.executable,__file__,'child',json.dumps(parent),str(lock_fd),
                 str(ns_fd if scope=='wan' else -1),'1' if tracked else '0',*args]
        descriptors=(lock_fd,ns_fd) if scope=='wan' else (lock_fd,)
        result=subprocess.run(command,pass_fds=descriptors,capture_output=True,text=True,timeout=8)
        if check_command and result.returncode:
            raise RuntimeError('Portal command failed: '+result.stderr[-1024:])
        if tracked: check()
        return result
    def host(args,check=True): return execute('host',args,check)
    def wan(args,check=True): return execute('wan',args,check)
    wan.namespace_name=NS
    return host,wan


def cleanup(lock_fd,ns_fd,session):
    import portal_network
    (ROOT/'cleaning').touch()
    host,wan=executors(lock_fd,ns_fd,session,False,lambda:None)
    network=portal_network.Network(ROOT,host,wan,lambda:None,lambda:fd_namespace(ns_fd,session))
    network.cleanup()
    request=load_json(WAN/'portal-resolve-request.json',{})
    if request.get('id')==session['id']: write_json(WAN/'portal-resolve-request.json',{})
    request=load_json(WAN/'portal-review-request.json',{})
    if request.get('id')==session['id']:
        write_json(WAN/'portal-review-request.json',{})
        write_json(WAN/'portal-review-result.json',{})
    write_json(ROOT/'status.json',{'state':'OFF','internet':False})
    write_json(ROOT/'result.json',{'cleaned':True,'errors':[]})


def guard(controller,lock_fd,ns_fd):
    import portal_guard
    import portal_request
    import portal_session
    private_root()
    signal.signal(signal.SIGHUP,signal.SIG_IGN)
    session=load_json(ROOT/'session.json',{})
    fd_namespace(ns_fd,session)
    write_json(ROOT/'guard.json',identity())
    def read(name):
        if name=='stop':
            if stopped():return True
            try:portal_request.check(session,alive)
            except RuntimeError:return True
            network=load_json(ROOT/'network.json',{})
            if network:
                try:
                    approved=portal_session.pin_set(session,load_json(WAN/'portal-pins.json',{}),time.monotonic())
                    lease=session['wan']['lease']
                    import portal_router
                    config=portal_router.plan(session['ap']['subnet'],session['device'],lease,
                                               approved['endpoints'],lease['gateway'])
                    if config!=network['config']:return True
                except (ValueError,KeyError,TypeError):return True
            return False
        if name=='heartbeat':
            try:return (ROOT/name).read_text()
            except FileNotFoundError:return ''
        return load_json(ROOT/(name+'.json'),{})
    def kill(owner,sig):
        if alive(owner):
            try:os.kill(owner['pid'],sig)
            except ProcessLookupError:pass
    try:
        portal_guard.supervise(controller,session['expires'],read,alive,kill,
                               lambda:cleanup(lock_fd,ns_fd,session),time.monotonic,time.sleep)
    except Exception:
        write_json(ROOT/'status.json',{'state':'CLEANUP_FAILED','internet':False})
        write_json(ROOT/'result.json',{'cleaned':False,'errors':['Portal cleanup incomplete']})
        raise
    finally:
        os.close(ns_fd);os.close(lock_fd)


def run(device_id,expected=None):
    import portal_access_session
    import portal_dns_server
    import portal_guard
    import portal_live
    import portal_network
    import portal_session
    import portal_request
    live=portal_live.system()
    inventory,bundle,result=live.inspect()
    if expected is None:
        session=portal_session.create(secrets.token_hex(12),device_id,inventory,bundle,result,time.monotonic(),alive)
    else:
        import copy
        session=copy.deepcopy(expected)
        portal_request.check(session,alive)
        portal_session.validate(session,inventory,bundle,result,time.monotonic(),alive)
        if session['device']['id']!=device_id:raise RuntimeError('Portal request device changed')
    import fcntl
    lock_fd=os.open(str(ROOT)+'.lock',os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    ns_fd=None
    guardian=None
    access=None
    registered=False
    try:
        info=os.fstat(lock_fd)
        if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_mode&0o077:
            raise RuntimeError('Unsafe portal runtime lock')
        fcntl.flock(lock_fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        ROOT.mkdir(mode=0o700,exist_ok=True);private_root()
        if (load_json(ROOT/'network.json',{}) or alive(load_json(ROOT/'controller.json',{}))
                or alive(load_json(ROOT/'guard.json',{}))):
            raise RuntimeError('Previous portal runtime not drained')
        for name in ('stop','cleaning'): (ROOT/name).unlink(missing_ok=True)
        handle=Path('/run/netns')/NS
        ns_fd=os.open(handle,os.O_RDONLY|os.O_NOFOLLOW)
        fd_namespace(ns_fd,session)
        live.check(session)
        portal_request.check(session,alive)
        owner=identity()
        write_json(ROOT/'session.json',session);write_json(ROOT/'controller.json',owner)
        registered=True
        write_json(ROOT/'mutation.json',{});write_json(ROOT/'result.json',{'cleaned':False})
        write_json(ROOT/'login-ready.json',{})
        pulse()
        guardian=subprocess.Popen([sys.executable,__file__,'guard',json.dumps(owner),str(lock_fd),str(ns_fd)],
                                   pass_fds=(lock_fd,ns_fd),stdin=subprocess.DEVNULL)
        deadline=time.monotonic()+3
        while time.monotonic()<deadline:
            if alive(load_json(ROOT/'guard.json',{})): break
            if guardian.poll() is not None: raise RuntimeError('Portal guard failed to start')
            time.sleep(.05)
        else:raise RuntimeError('Portal guard startup timeout')
        def check():
            portal_request.check(session,alive)
            if stopped() or not alive(load_json(ROOT/'guard.json',{})):
                raise RuntimeError('Portal guard unavailable')
            fd_namespace(ns_fd,session)
            live.check(session)
            pulse()
        host,wan=executors(lock_fd,ns_fd,session,True,check)
        network=portal_network.Network(ROOT,host,wan,check,lambda:fd_namespace(ns_fd,session))
        def request(value):
            check()
            write_json(WAN/'portal-resolve-request.json',value)
            if load_json(WAN/'portal-review-request.json',{}) != value:
                write_json(WAN/'portal-review-result.json',{})
                write_json(WAN/'portal-review-request.json',value)
            check()
        access=portal_access_session.Access(session,check,lambda:load_json(WAN/'portal-pins.json',{}),
                                           request,network,portal_dns_server.Broker)
        def terminate(*args):raise SystemExit()
        signal.signal(signal.SIGTERM,terminate)
        signal.signal(signal.SIGINT,terminate)
        while True:
            state=access.step()
            if state=='LOGIN_READY' and not load_json(ROOT/'login-ready.json',{}):
                check()
                write_json(ROOT/'login-ready.json',{'id':session['id'],'owner':owner,
                                                    'ready_at':time.monotonic()})
            write_json(ROOT/'status.json',{'state':state,'internet':False,'device_id':device_id})
            if state=='WAITING_TARGETS':time.sleep(.2)
    finally:
        if access and access.broker is not None: access.broker.close()
        # On normal exit the independent guard drains commands and networking.
        # A dead guard requires inline drain using the same owner-token policy.
        if ns_fd is not None and registered and (guardian is None or guardian.poll() is not None):
            portal_guard.supervise(identity(),time.monotonic()-1,lambda name:
                True if name=='stop' else load_json(ROOT/(name+'.json'),{}),
                lambda owner:False if owner==identity() else alive(owner),
                lambda owner,sig:os.kill(owner['pid'],sig) if alive(owner) else None,
                lambda:cleanup(lock_fd,ns_fd,session),time.monotonic,time.sleep)
        if ns_fd is not None:os.close(ns_fd)
        os.close(lock_fd)


if __name__=='__main__':
    if sys.argv[1]=='child':child(json.loads(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4]),sys.argv[6:],sys.argv[5]=='1')
    elif sys.argv[1]=='guard':guard(json.loads(sys.argv[2]),int(sys.argv[3]),int(sys.argv[4]))
    elif sys.argv[1]=='start':run(sys.argv[2])
    elif sys.argv[1]=='requested':
        import portal_request
        intent=portal_request.read(sys.argv[2],alive)
        session=intent['session'];session['request_owner']=intent['owner']
        run(session['device']['id'],session)
    elif sys.argv[1]=='stop':stop()
    else:raise ValueError('Unknown portal runtime action')
