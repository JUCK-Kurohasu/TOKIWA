import socket, types
from tokiwa.sensors.host import HostSensor
from collections import namedtuple
C=namedtuple("C","family type laddr raddr status pid")
class FakePs:
    class AccessDenied(Exception): pass
    class NoSuchProcess(Exception): pass
    class ZombieProcess(Exception): pass
    conns=[]
    def net_connections(self,kind): return self.conns
    def net_if_addrs(self): return {}
    def Process(self,pid): raise self.NoSuchProcess()
ps=FakePs()
ps.conns=[C(socket.AF_INET,socket.SOCK_STREAM,("10.0.0.5",22),None,"LISTEN",1)]
h=HostSensor("s","h",psutil_module=ps,max_connections=1000)
h.collect_events()
# cycle 2: attacker-controlled noise (1200 SYN_RECV from spoofed/loopback) + 1 C2 outbound inserted first by kernel order
noise=[C(socket.AF_INET,socket.SOCK_STREAM,("10.0.0.5",22),(f"198.51.100.{i%250}",10000+i),"SYN_RECV",None) for i in range(1200)]
c2=C(socket.AF_INET,socket.SOCK_STREAM,("10.0.0.5",45000),("203.0.113.66",443),"ESTABLISHED",4242)
ps.conns=ps.conns[:1]+noise+[c2]
ev=h.collect_events()
conn=[e for e in ev if e.kind.value=="connection"]
print("cycle2 connection events:",len(conn),"c2 reported:",any(e.destination.ip=="203.0.113.66" for e in conn))
ps.conns=ps.conns[:1]+[c2]
ev=h.collect_events(); conn=[e for e in ev if e.kind.value=="connection"]
print("cycle3 (noise gone, c2 still open) connection events:",len(conn),"c2 reported:",any(e.destination.ip=="203.0.113.66" for e in conn))
