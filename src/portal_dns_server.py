"""Bounded session DNS listener; the caller validates session and approved pins.

No upstream resolver is used. check() must verify AP/WAN/process/client ownership
and absolute session expiry; pins() returns only independently validated pins.
The session guard owns closing this listener and revoking its firewall rules.
"""
import ipaddress
import re
import selectors
import socket
import struct
import time
from portal_dns_broker import answer


class Broker:
    def __init__(self, address, client, interface, check, pins, port=5354):
        self.address=str(ipaddress.IPv4Address(address))
        self.client=str(ipaddress.IPv4Address(client))
        if not isinstance(interface,str) or not re.fullmatch(r'[A-Za-z0-9_.:-]{1,15}',interface):
            raise ValueError('Portal DNS requires a selected interface')
        if type(port) is not int or not 1<=port<=65535: raise ValueError('Invalid DNS listener port')
        self.check,self.pins=check,pins
        self.selector=selectors.DefaultSelector()
        self.sockets=[]
        try:
            for kind in (socket.SOCK_DGRAM,socket.SOCK_STREAM):
                self.check()
                sock=socket.socket(socket.AF_INET,kind)
                self.sockets.append(sock)
                sock.setsockopt(socket.SOL_SOCKET,socket.SO_BINDTODEVICE,interface.encode()+b'\0')
                sock.bind((self.address,port))
                if kind==socket.SOCK_STREAM: sock.listen(4)
                sock.setblocking(False)
                self.selector.register(sock,selectors.EVENT_READ)
                self.check()
        except BaseException:
            self.close()
            raise

    def close(self):
        self.selector.close()
        for sock in self.sockets: sock.close()
        self.sockets=[]

    def reply(self, packet):
        self.check()
        pins=self.pins()
        result=answer(packet,pins,time.monotonic())
        self.check()
        return result

    def poll(self, timeout=.2):
        if not self.sockets: raise RuntimeError('Portal DNS listener closed')
        try:
            self.check()
            for key,_ in self.selector.select(min(max(timeout,0),.2)):
                self.check()
                sock=key.fileobj
                if sock.type==socket.SOCK_DGRAM:
                    try: packet,peer=sock.recvfrom(513)
                    except BlockingIOError: continue
                    if peer[0]!=self.client: continue
                    try: reply=self.reply(packet)
                    except ValueError:
                        # A malformed packet is ignored. A revoked session is
                        # checked separately and must terminate the listener.
                        self.check()
                        continue
                    self.check()
                    sock.sendto(reply,peer)
                else:
                    try: connection,peer=sock.accept()
                    except BlockingIOError: continue
                    with connection:
                        if peer[0]!=self.client: continue
                        # Include the ownership checks in a bounded frame
                        # budget that also works on the Venus Pi.
                        deadline=time.monotonic()+2
                        def read(size):
                            data=b''
                            while len(data)<size:
                                self.check()
                                remaining=deadline-time.monotonic()
                                if remaining<=0: raise TimeoutError('DNS frame timeout')
                                connection.settimeout(remaining)
                                part=connection.recv(size-len(data))
                                if not part: raise EOFError('Incomplete DNS frame')
                                data+=part
                            return data
                        try:
                            size=struct.unpack('!H',read(2))[0]
                            if not 12<=size<=512: continue
                            reply=self.reply(read(size))
                            self.check()
                            remaining=deadline-time.monotonic()
                            if remaining<=0: continue
                            connection.settimeout(remaining)
                            connection.sendall(struct.pack('!H',len(reply))+reply)
                        except (OSError,EOFError,ValueError):
                            self.check()
        except BaseException:
            self.close()
            raise
