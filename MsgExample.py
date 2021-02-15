import random

def generateXID() -> hex:
    
    rez: hex = 0x0
    
    nrOcteti = 4
    
    for i in range(nrOcteti):
        
        rez *= 0x10
        
        rez += random.randint(0x0, 0xf)
        
        rez *= 0x10
        
        rez += random.randint(0x0, 0xf)
    
    return rez

def generateMAC() -> hex:
    
    rez: hex = 0x0
    
    nrOcteti = 6
    
    for i in range(nrOcteti):
        
        rez *= 0x10
        
        rez += random.randint(0x0, 0xf)
        
        rez *= 0x10
        
        rez += random.randint(0x0, 0xf)
    
    return rez
            

        
class message:

    _Serv = None

    _op: hex
    
    _hType: hex
    
    _hLen: hex
    
    _hops: hex
    
    _xid: hex
    
    _secs: hex
    
    _flags: hex
    
    _ciaddr: hex
    
    _yiaddr: hex
    
    _siaddr: hex
    
    _giaddr: hex
    
    _chaddr: hex
    
    _sname: hex
    
    _file: hex
    
    _MagCookie: hex
    
    _options: list
    
    def __init__(self, serv, op: hex, hType: hex, hLen: hex, hops: hex, xid: hex, secs: hex, flags: hex, ciaddr: hex, yiaddr: hex, siaddr: hex, giaddr: hex, chaddr: hex, sname: hex, file: hex, options: hex):

        self._Serv = serv

        self._op = op
    
        self._hType = hType
        
        self._hLen = hLen
        
        self._hops = hops
        
        self._xid = xid
        
        self._secs = secs
        
        self._flags = flags
        
        self._ciaddr = ciaddr
        
        self._yiaddr = yiaddr
        
        self._siaddr = siaddr
        
        self._giaddr = giaddr
        
        self._chaddr = chaddr
        
        self._sname = sname
        
        self._file = file
        
        self._MagCookie = 0x63825363
        
        self._options = options
         
    def __str__(self) -> str:
        
        rez: str = ''
        
        rez += 'Op code = ' + hex(self._op) + '\n'
        
        rez += 'Hardware Type = ' + hex(self._hType) + '\n'
        
        rez += 'Hardware Address Length = ' + hex(self._hLen) + '\n'
        
        rez += 'Hops = ' + hex(self._hops) + '\n'
        
        rez += 'Transaction ID = ' + hex(self._xid) + '\n'
        
        rez += 'Seconds = ' + hex(self._secs) + '\n'
        
        rez += 'Flags = ' + hex(self._flags) + '\n'
        
        rez += 'Client IP Address = ' + hex(self._ciaddr) + '\n'
        
        rez += 'Your IP Address = ' + hex(self._yiaddr) + '\n'
        
        rez += 'Server IP Address = ' + hex(self._siaddr) + '\n'
        
        rez += 'Gateway IP Address = ' + hex(self._giaddr) + '\n'
        
        rez += 'Client Ethernet Address = ' + hex(self._chaddr) + '\n'
        
        rez += 'Serever Host Name = ' + self._sname.__str__() + '\n'
        
        rez += 'Boot File Name = ' + self._file.__str__() + '\n'
        
        rez += 'Magic Cookie = ' + hex(self._MagCookie) + '\n'
        
        rez += 'Options: ' + self._options.__str__() + '\n'
        
        return rez
    
    def process(self):
        pass
    
    def setOptField(self, opt: list):
        self._options = opt
    
    def getMAC(self) -> int:
    
        return self._chaddr
    
    def getXID(self) -> int:
        return self._xid
    
    def getServerID(self) -> int:
        return self._siaddr
        
class ServerMessage(message):
    
    def __init__(self, serv, hType: hex, hLen: hex, hops: hex, xid: hex, secs: hex, flags: hex, ciaddr: hex, yiaddr: hex, siaddr: hex, giaddr: hex, chaddr: hex, sname: hex, file: hex):
        
        super().__init__(serv, 0x2, hType, hLen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file, None)
    
    def process(self) -> message:
        pass
    
class ClientMessage(message):

    def __init__(self, serv, hType: hex, hLen: hex, hops: hex, xid: hex, secs: hex, flags: hex, ciaddr: hex, yiaddr: hex, siaddr: hex, giaddr: hex, chaddr: hex, sname: hex, file: hex):
        
        super().__init__(serv, 0x1, hType, hLen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file, None)
    
    def process(self) -> message:
        pass
    
class DHCP_Discover(ClientMessage):
    
    def __init__(self, serv, hType: hex, hLen: hex, hops: hex, xid: hex, secs: hex, flags: hex, ciaddr: hex, yiaddr: hex, siaddr: hex, giaddr: hex, chaddr: hex, sname: hex, file: hex):
        
        super().__init__(serv, hType, hLen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file)
        
        self._options = [hex(0x350101), hex(0x3204C0A80164), hex(0x370401030f06), hex(0xFF)]
    
    def process(self) -> message:
        
        lease = None
        
        #decodifica lista self._options pentru a verifica daca exista codul "51"
        
        opt: list = []
        
        rez: DHCP_Offer = DHCP_Offer(self._Serv, self._hType, self._hLen, self._hops, self._xid, self._secs, self._flags, self._ciaddr, self._Serv.aloca(lease), self._Serv.getServerID(), self._giaddr, self._chaddr, self._sname, self._file)
        
        self._Serv.setMessage(rez)
        
        opt.append(self._Serv.genCode(53))
        
        opt.append(self._Serv.genCode(1))
        
        opt.append(self._Serv.genCode(3))
        
        opt.append(self._Serv.genCode(51))
        
        opt.append(self._Serv.genCode(54))
        
        opt.append(self._Serv.genCode(6))
        
        opt.append(hex(0xff))
        
        rez.setOptField(opt)
        
        return rez
          
class DHCP_Offer(ServerMessage):
    
    def __init__(self, serv, hType: hex, hLen: hex, hops: hex, xid: hex, secs: hex, flags: hex, ciaddr: hex, yiaddr: hex, siaddr: hex, giaddr: hex, chaddr: hex, sname: hex, file: hex):
        
        super().__init__(serv, hType, hLen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file)
        
        self._options = None
    
    def process(self) -> message:
        return None
    
class DHCP_Request(ClientMessage):

    def __init__(self, serv, hType: hex, hLen: hex, hops: hex, xid: hex, secs: hex, flags: hex, ciaddr: hex, yiaddr: hex, siaddr: hex, giaddr: hex, chaddr: hex, sname: hex, file: hex):
        
        super().__init__(serv, hType, hLen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file)
        
        self._options = [hex(0x350103), hex(0x3204C0A80164), hex(0xFF)]
  
    def process(self) -> message:
        
        lease = None
        
        #decodifica lista self._options pentru a verifica daca exista codul "51"
        
        opt: list = []
        
        rez: ServerMessage
        
        if self._Serv.seteaza(int(self._ciaddr), lease) == True:
            rez = DHCP_Ack(self._Serv, self._hType, self._hLen, self._hops, self._xid, self._secs, self._flags, self._ciaddr, self._yiaddr, self._Serv.getServerID(), self._giaddr, self._chaddr, self._sname, self._file)
        else:
            rez = DHCP_Nak(self._Serv, self._hType, self._hLen, self._hops, self._xid, self._secs, self._flags, self._ciaddr, self._yiaddr, self._Serv.getServerID(), self._giaddr, self._chaddr, self._sname, self._file)

        self._Serv.setMessage(rez)
        
        opt.append(self._Serv.genCode(53))
        
        opt.append(self._Serv.genCode(1))
        
        opt.append(self._Serv.genCode(3))
        
        opt.append(self._Serv.genCode(51))
        
        opt.append(self._Serv.genCode(54))
        
        opt.append(self._Serv.genCode(6))
        
        opt.append(0xff)
        
        rez.setOptField(opt)
        
        return rez
    
class DHCP_Ack(ServerMessage):

    def __init__(self, serv, hType: hex, hLen: hex, hops: hex, xid: hex, secs: hex, flags: hex, ciaddr: hex, yiaddr: hex, siaddr: hex, giaddr: hex, chaddr: hex, sname: hex, file: hex):
        
        super().__init__(serv, hType, hLen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file)
        
        self._options = None
    
    def process(self) -> message:
        return None

class DHCP_Nak(ServerMessage):

    def __init__(self, serv, hType: hex, hLen: hex, hops: hex, xid: hex, secs: hex, flags: hex, ciaddr: hex, yiaddr: hex, siaddr: hex, giaddr: hex, chaddr: hex, sname: hex, file: hex):
        
        super().__init__(serv, hType, hLen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file)
        
        self._options = None
    
    def process(self) -> message:
        return None

class DHCP_Decline(ClientMessage):
    
    def __init__(self, serv, hType: hex, hLen: hex, hops: hex, xid: hex, secs: hex, flags: hex, ciaddr: hex, yiaddr: hex, siaddr: hex, giaddr: hex, chaddr: hex, sname: hex, file: hex):
        
        super().__init__(serv, hType, hLen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file)
        
        self._options = [hex(0x350104), hex(0x3204C0A80164), hex(0xFF)]
  
    def process(self) -> message:
        
        self._Serv.blackList(self._ciaddr)

class DHCP_Release(ClientMessage):
    
    def __init__(self, serv, hType: hex, hLen: hex, hops: hex, xid: hex, secs: hex, flags: hex, ciaddr: hex, yiaddr: hex, siaddr: hex, giaddr: hex, chaddr: hex, sname: hex, file: hex):
        
        super().__init__(serv, hType, hLen, hops, xid, secs, flags, ciaddr, yiaddr, siaddr, giaddr, chaddr, sname, file)
        
        self._options = [hex(0x350104), hex(0x3204C0A80164), hex(0xFF)]
    
    def process(self) -> message:
        
        self._Serv.release(self._ciaddr)

def genMessage(mess: ServerMessage) -> ClientMessage:
    if mess.__class__.__name__ == 'DHCP_Offer':
        if random.randint(0, 1) == 1:
            return DHCP_Request(mess._Serv, mess._hType, mess._hLen, mess._hops, mess._xid, mess._secs, mess._flags, mess._yiaddr, mess._ciaddr, mess.getServerID(), mess._giaddr, mess._chaddr, mess._sname, mess._file)
        else:
            return DHCP_Decline(mess._Serv, mess._hType, mess._hLen, mess._hops, mess._xid, mess._secs, mess._flags, mess._yiaddr, mess._ciaddr, mess.getServerID(), mess._giaddr, mess._chaddr, mess._sname, mess._file)
    elif mess.__class__.__name__ == 'DHCP_Nak':
        return DHCP_Discover(mess._Serv, mess._hType, mess._hLen, mess._hops, mess._xid, mess._secs, mess._flags, mess._yiaddr, mess._ciaddr, mess.getServerID(), mess._giaddr, mess._chaddr, mess._sname, mess._file)
    
if __name__ == '__main__':

    mesajServ: DHCP_Offer = DHCP_Offer(0x1, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, None, None)
    
    mesajClie: DHCP_Discover = DHCP_Discover(0x1, 0x6, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, None, None)
    