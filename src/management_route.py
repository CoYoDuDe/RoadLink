"""Read-only, generation-checked IPv4 VPN route for SSH management.

This is a prerequisite for tunnel binding, not a WLAN failover claim. It never
changes routes, firewall rules, SSH settings, keys or reverse listeners.
"""
import argparse
import ipaddress
import json
import math
import os
from pathlib import Path
import stat
import subprocess
import time

ROOT=Path('/run/roadlink-vpn')
INTERFACE='wgroadlink'
ALIAS='roadlink-vpn-owned'
READ_BUDGET=3.0


def pairs(items):
    result={}
    for key,value in items:
        if key in result:raise ValueError('Duplicate field')
        result[key]=value
    return result


def fresh(stamp,now,ttl):
    return (type(stamp) in (int,float) and type(now) in (int,float)
            and math.isfinite(stamp) and math.isfinite(now)
            and stamp>0 and 0<=now-stamp<=ttl)


def identity_alive(value,proc=Path('/proc')):
    if (type(value) is not dict or set(value)!={'pid','start'}
            or type(value['pid']) is not int or not 0<value['pid']<2147483648
            or type(value['start']) is not str or not value['start'].isdigit()
            or not 0<len(value['start'])<=20):return False
    try:
        root=proc/str(value['pid'])
        if root.stat().st_uid!=0:return False
        fields=(root/'stat').read_text().rsplit(')',1)[1].split()
        return fields[0] not in ('Z','X') and fields[19]==value['start']
    except (OSError,ValueError,IndexError):return False


def stamp(info):
    return (info.st_dev,info.st_ino,info.st_size,info.st_mtime_ns,info.st_ctime_ns)


def read_file(directory,name,limit):
    # Runtime writers publish with atomic replace. A read may hold the old
    # inode after its name is gone; discard it and reopen, never accept its
    # bytes or reuse a previous route result. All final authority checks and
    # the shared snapshot deadline still apply.
    retry_until=time.monotonic()+.05
    for attempt in range(4):
        descriptor=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=directory)
        try:
            before=os.fstat(descriptor)
            if (not stat.S_ISREG(before.st_mode) or before.st_uid!=0 or before.st_mode&0o022
                    or before.st_nlink not in (0,1) or not 0<before.st_size<=limit):
                raise ValueError('Unsafe runtime file')
            if before.st_nlink==1:
                with os.fdopen(descriptor,'rb',closefd=False) as stream:data=stream.read(limit+1)
                try:named=os.stat(name,dir_fd=directory,follow_symlinks=False)
                except FileNotFoundError:named=None
                current=os.fstat(descriptor)
                if (len(data)==before.st_size and current.st_nlink==1
                        and named is not None and named.st_nlink==1 and stamp(before)==stamp(current)
                        and stamp(before)==stamp(named)):
                    return data
                # Only removal of this still-unchanged inode permits retry.
                # In-place writes, changed ownership/mode and hardlinks fail.
                unchanged=('st_dev','st_ino','st_mode','st_uid','st_gid','st_size','st_mtime_ns')
                if (current.st_nlink!=0 or len(data)!=before.st_size
                        or any(getattr(before,k)!=getattr(current,k) for k in unchanged)):
                    raise ValueError('Runtime file replaced or modified')
        finally:os.close(descriptor)
        if attempt==3 or time.monotonic()>=retry_until:
            raise ValueError('Runtime publication did not settle')


def command(args,timeout=1.5):
    result=subprocess.run(args,capture_output=True,text=True,timeout=timeout,check=False)
    if result.returncode or len(result.stdout)>32768:raise ValueError('Kernel observation unavailable')
    return json.loads(result.stdout,object_pairs_hook=pairs)


def kernel(endpoint,address,run):
    link=run(['ip','-j','link','show','dev',INTERFACE])
    addresses=run(['ip','-j','-4','addr','show','dev',INTERFACE])
    route=run(['ip','-j','-4','route','get',endpoint,'from',address])
    if not all(type(rows) is list and len(rows)==1 and type(rows[0]) is dict for rows in (link,addresses,route)):
        raise ValueError('Ambiguous kernel observation')
    link,addresses,route=link[0],addresses[0],route[0]
    index=link.get('ifindex')
    if (type(index) is not int or index<=0 or link.get('ifname')!=INTERFACE
            or link.get('ifalias')!=ALIAS or 'UP' not in link.get('flags',[])
            or addresses.get('ifindex')!=index or addresses.get('ifname')!=INTERFACE
            or not any(type(row) is dict and row.get('family')=='inet' and row.get('local')==address
                       for row in addresses.get('addr_info',[]))
            or route.get('dev')!=INTERFACE or str(route.get('table'))!='51890'
            or route.get('dst')!=endpoint or route.get('from',route.get('prefsrc'))!=address
            or route.get('type','unicast')!='unicast' or route.get('gateway')):
        raise ValueError('Management source or route changed')
    return index


def snapshot(endpoint,root=ROOT,clock=time.monotonic,wallclock=time.time,alive=identity_alive,run=None):
    """Return a private local route description, or None on any unproved gate."""
    directory=None
    try:
        deadline=time.monotonic()+READ_BUDGET
        def remaining():
            left=deadline-time.monotonic()
            if left<=0:raise subprocess.TimeoutExpired('management route observation',READ_BUDGET)
            return left
        def bounded(args):
            left=remaining()
            result=command(args,timeout=min(1.5,left)) if run is None else run(args)
            remaining()
            return result
        endpoint=ipaddress.IPv4Address(endpoint)
        if not endpoint.is_global or endpoint.is_multicast or endpoint.is_reserved:return None
        endpoint=str(endpoint);root=Path(root)
        for folder in (root.parent,root):
            info=folder.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid!=0 or info.st_mode&0o022:return None
        directory=os.open(str(root),os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC)
        original=os.fstat(directory)
        def observe():
            while True:
                remaining()
                for name in ('stop','cleaning','result.json'):
                    try:os.stat(name,dir_fd=directory,follow_symlinks=False)
                    except FileNotFoundError:continue
                    raise ValueError('Runtime stopping')
                controller=json.loads(read_file(directory,'controller.json',4096),object_pairs_hook=pairs)
                guard=json.loads(read_file(directory,'guard.json',4096),object_pairs_hook=pairs)
                state=json.loads(read_file(directory,'status.json',262144),object_pairs_hook=pairs)
                heartbeat=float(read_file(directory,'heartbeat',128))
                now=clock()
                if (type(state) is not dict or state.get('state') not in ('READY','CONNECTING')
                        or state.get('wan') not in ('ethernet','wifi')
                        or type(state.get('internet')) is not bool or type(state.get('dns_ready')) is not bool
                        or state.get('owner')!=controller or state.get('guard')!=guard
                        or not alive(controller) or not alive(guard) or not fresh(heartbeat,now,10)
                        or not fresh(state.get('handshake'),wallclock(),180)):
                    raise ValueError('Runtime not current')
                # New controllers date their actual handshake/route check
                # separately from slow Internet probes. Legacy controllers
                # keep the original contract. An explicitly invalid new
                # observation must never fall back to an older health result.
                checked_at=state.get('management_checked_at',state.get('checked_at'))
                if not fresh(checked_at,now,15):
                    # A slow health probe can publish just after the previous
                    # status expires. Wait only inside this snapshot's existing
                    # budget, then validate the new files from scratch. Never
                    # return the old status or extend its freshness threshold.
                    if not fresh(checked_at,now,15+READ_BUDGET):
                        raise ValueError('Runtime status expired')
                    time.sleep(min(.05,remaining()))
                    continue
                interface=ipaddress.IPv4Interface(state['address'])
                address=str(interface.ip)
                if interface.network.prefixlen!=32 or not any(interface.ip in ipaddress.IPv4Network(block)
                        for block in ('10.0.0.0/8','172.16.0.0/12','192.168.0.0/16')):
                    raise ValueError('Invalid VPN source')
                return controller,guard,address
        before=observe();index=kernel(endpoint,before[2],bounded)
        if observe()!=before or kernel(endpoint,before[2],bounded)!=index:raise ValueError('Generation changed')
        final=root.lstat()
        if (final.st_dev,final.st_ino)!=(original.st_dev,original.st_ino):raise ValueError('Runtime directory replaced')
        if observe()!=before:raise ValueError('Authority revoked')
        remaining()
        return dict(schema=1,mode='VPN',endpoint=endpoint,address=before[2],interface=INTERFACE,
                    ifindex=index,controller=before[0],guard=before[1],
                    runtime=[original.st_dev,original.st_ino])
    except (OSError,ValueError,TypeError,KeyError,subprocess.TimeoutExpired):return None
    finally:
        if directory is not None:os.close(directory)


def main():
    parser=argparse.ArgumentParser(description='Read-only private management route; no network changes')
    parser.add_argument('--endpoint',required=True)
    result=snapshot(parser.parse_args().endpoint)
    print(json.dumps(result,separators=(',',':'),allow_nan=False))
    return 0 if result is not None else 1


if __name__=='__main__':raise SystemExit(main())
