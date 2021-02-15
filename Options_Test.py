 
class Option:

    __Serv = None
    
    def __init__(self, ser):
        self.__Serv = ser

    def genCode(self, code: int) -> hex:
        
        if code == 53:
        
            return self.__DHCP_Message_Type()
        
        elif code == 1:
        
            return self.__Subnet_Mask()
            
        elif code == 3:
        
            return self.__Router_Option()

        elif code == 6:
            
            return self.__DNS_Option()
            
        elif code == 51:
            
            return self.__Lease_Time()
            
        elif code == 54:
            
            return self.__DHCP_Server()

    def __DHCP_Message_Type(self) -> hex:
 
        rez: hex = 0x350100
        
        if self.__Serv._Message.__class__.__name__ == 'DHCP_Offer':
            
            rez += 0x02
        
        elif self.__Serv._Message.__class__.__name__ == 'DHCP_Ack':
        
            rez += 0x05

        elif self.__Serv._Message.__class__.__name__ == 'DHCP_Nak':
        
            rez += 0x06

        return hex(rez)

    def __DNS_Option(self) -> hex:
        
        rez: hex = 0x600
        
        rez += self.__Serv._DNSServer.__len__() * 4
        
        for i in self.__Serv._DNSServer:
        
            rez *= 0x10 ** 0x8
            
            rez += i
        
        return hex(rez)

    def __Subnet_Mask(self) -> hex:
        
        return hex(0x10400000000 + int(self.__Serv._SubnetMask))
    
    def __Router_Option(self) -> hex:
        
        rez: hex = 0x0300
        
        rez += (0x04 * self.__Serv._RouterAddr.__len__())
                
        for i in self.__Serv._RouterAddr:
            
            rez *= (0x10**0x8)
            
            rez += i
        
        return hex(rez)
        
    def __Lease_Time(self) -> hex:
    
        rez: hex = 0x330400000000
        
        rez += self.__Serv._Lease
        
        return hex(rez)
        
    def __DHCP_Server(self) -> hex:
    
        rez: hex = 0x360400000000
        
        rez += self.__Serv._ServerIdentifier
        
        return hex(rez)
        
    