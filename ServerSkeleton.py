import datetime
import random
import threading
from Options_Test import Option
from MsgExample import *

coada: list = []

myLock: bool = False

class Server:
    
    _SubnetMask: hex
    
    _RouterAddr: list
    
    _ServerIdentifier: hex
    
    _firstAddr: hex
    
    _lastAddr: hex
    
    _Lease: hex
    
    _DNSServer: list
    
    _Message = None
    
    _OptionGen = None
    
    def __init__(self):
        
        self._SubnetMask = 0xFFFFF000
        
        self._RouterAddr = [0x9D363097, 0x9d3630b2]
        
        self._ServerIdentifier = 0x9D363001
        
        self._firstAddr = 0x9D363002
        
        self._lastAddr = 0x9D363480
        
        self._Lease = 60
        
        self._DNSServer = [0x8080404, 0x8080808]
        
        self._OptionGen = Option(self)
        
        with open('Address_Pool.txt', 'w') as f:
            for i in range(self._firstAddr, self._lastAddr):
                    f.write(str(i) + ' : ' + str((None, None)) + "\n")
        
       
    #Metoda ce are rol de a cauta si rezerva o adresa disponibila din "address pool" 
    #Aceasta metoda este apelata in momentul in care Serverul primeste un mesaj DHCPDISCOVER si trimite un mesaj DHCPOFFER
    def aloca(self, reqTime: int) -> hex:
    
        fila: list
        
        flag: int = 0
        
        rez: hex = None
        
        with open('Address_Pool.txt', 'r') as f:
            fila = f.readlines()
            
        with open('Address_Pool.txt', 'w') as f:
            for i in fila:
                if (i[14:18] == 'None' and i[20:24] == 'None' or datetime.datetime.now().strftime("%D%H%M%S").__str__() >= i[i.find(',') + 2:i.__len__()-2]) and flag == 0:
                    flag = 1
                    rez = int(i[:i.find(':')-1])
                    if reqTime == None:
                        f.write(i[:i.find('(') + 1] + 'None, ' + (datetime.datetime.now() + datetime.timedelta(seconds=self._Lease)).strftime("%D%H%M%S") +')\n')
                    elif reqTime > 0:
                        f.write(i[:i.find('(') + 1] + 'None, ' + (datetime.datetime.now() + datetime.timedelta(seconds=reqTime)).strftime("%D%H%M%S") +')\n')
                    else:
                        print('Valoare reqTime negativa!!!')
                else:
                    f.write(i);
                    
        return rez

    #Metoda ce are rol de a stabili intentia clientului de a folosi serviciile Serverului 
    #Astfel Serverul poate:  -fie sa asigneze o adresa ip clientului <<aici se include si cazul alocarii statice>> si v-a returna o valoare True
    #                        -fie sa elibereze adresa ip aceasta putand in cele din urma sa fie realocata si v-a returna o valoare False
    #Acesta metoda este apelata in momentul in care Serverul primeste un mesaj DHCPREQUEST si trebuie sa determine daca v-a returna un mesaj DHCPACK "True" sau un mesaj DHCPNAK "False"
    def seteaza(self, addr: int, reqTime: int) -> bool:
        
        fila: list
        
        rez: bool = False
        with open('Address_Pool.txt', 'r') as f:
            fila = f.readlines()
            
        with open('Address_Pool.txt', 'w') as f:
            for i in fila:
                if int(i[:i.find(' ')]) == addr: #Verifica daca s-a ajuns la adresa specificata in mesaj-> T: Urmatorul pas | F: Scrie mesajul fara modificari
                    if self.getServerID() == self._Message.getServerID(): #Verifica daca ID-ul mesajului corespunde cu ID-ul serverului-> T: Urmatorul pas | F: reseteaza adresa rezervata
                        if i[i.find(',') + 2 : i.__len__() - 2] == 'None' and int(i[i.find('(') + 1 : i.find(',')]) == self._Message.getMAC(): #Verifica daca clientul are alocata o adresa statica-> T: Aloca adresa | F: Urmatorul if
                            rez = True
                            f.write(i)
                        elif datetime.datetime.now().strftime("%D%H%M%S").__str__() < i[i.find(',') + 2:i.__len__()-2] and (i[i.find('(') + 1 : i.find('(') + 5] == 'None' or int(i[i.find('(') + 1 : i.find(',')]) == self._Message.getMAC()): #Daca lease_time-ul este valabil si (adresa este valabila sau este alocata deja clientului)-> T: Aloca adresa | F: Urmatorul elif
                            rez = True
                            if reqTime == None: # Daca in mesaj nu este specificat un lease_time de catre client-> F: Serverul aloca timp-ul cerut | T: Serverul aloca timpul standard
                                f.write(i[:i.find('(') + 1] + self._Message.getMAC().__str__() +', ' + (datetime.datetime.now() + datetime.timedelta(seconds=self._Lease)).strftime("%D%H%M%S") +')\n')
                            elif reqTime > 0:
                                f.write(i[:i.find('(') + 1] + self._Message.getMAC().__str__() +', ' + (datetime.datetime.now() + datetime.timedelta(seconds=reqTime)).strftime("%D%H%M%S") +')\n')
                            else:
                                print('Valoare reqTime negativa!!!')
                        elif datetime.datetime.now().strftime("%D%H%M%S").__str__() >= i[i.find(',') + 2:i.__len__()-2]: #and (i[i.find('(') + 1 : i.find('(') + 5] == 'None' or int(i[i.find('(') + 1 : i.find(',')]) == self._Message.getMAC()): #Daca lease_time-ul este depasit si (adresa este valabila sau este alocata deja clientului)-> T: Reseteaza adresa | F: Scrie adresa nemodificata
                            rez = False
                            f.write(i[:i.find('(') + 1] + 'None, None)\n')
                        else:
                            f.write(i)
                    else:
                        rez = False
                        f.write(i[:i.find('(') + 1] + 'None, None)\n')
                else:
                    f.write(i)
                    
        return rez
    
    #Metoda ce are rol de a marca o adresa din "address pool" ca fiind deja in uz de catre un alt client
    #Aceasta adresa v-a fi omisa pentru o perioada prestabilita de timp
    #Metoda este apelata in momentul in care Serverul primeste un mesaj de tip DHCPDECLINE
    def blackList(self, addr: int):
        
        fila: list
        
        with open('Address_Pool.txt', 'r') as f:
            fila = f.readlines()
            
        with open('Address_Pool.txt', 'w') as f:
            for i in fila:
                if int(i[:i.find(' ')]) == addr:
                    f.write(i[:i.find(',') + 2] + (datetime.datetime.now() + datetime.timedelta(seconds=self._Lease)).strftime("%D%H%M%S").__str__() +')\n')
                else:
                    f.write(i)
    
    
    #Metoda ce are ca rol eliberarea unei adrese din "address pool" in momentul in care se primeste un mesaj de tip DHCPRELEASE
    def release(self, addr: int):
        
        fila: list
        
        with open('Address_Pool.txt', 'r') as f:
            fila = f.readlines()
            
        with open('Address_Pool.txt', 'w') as f:
            for i in fila:
                if int(i[:i.find(' ')]) == addr:
                    f.write(i[:i.find('(') + 1] + 'None, None)\n')
                else:
                    f.write(i)
    
    #Getter pentru ID-ul Serverului <<siaddr - Server IP Address>>
    def getServerID(self) -> hex:
        
        return self._ServerIdentifier
    
    
    #Metoda ce primeste ca parametru un numar specific unei optiuni si retureaza valoarea in hexazecimal a codului  
    def genCode(self, code: int) -> hex:
    
        return self._OptionGen.genCode(code)
    
    
    #Metoda care afiseaza continutul mesajelor transmise dintre un client si Serverul curent
    def afisare(self):
        #with open('Address_Pool.txt', 'r') as f:
        #    for i in f:
        #        if i[14:18] != 'None':
        #            print('Am gasit adresa: ' + hex(int(i[:i.find(' ')])))
        
        global myLock
        
        while True:
            if coada.__len__() > 0:
                while True:
                    if not myLock:
                        break
                myLock = True
                if coada[0] != None:
                    self._Message = coada.pop()
                    print(self._Message)
                    self._Message = self._Message.process()
                    print(self._Message)
                    print()
                    coada.append(genMessage(self._Message))
                else:
                    coada.pop()
                myLock = False
        '''print(self._Message)
        print()
        self._Message = self._Message.process()
        print(self._Message)
        print()
        #self._Message = DHCP_Decline(self._Message)
        self._Message = DHCP_Request(self._Message)
        print(self._Message)
        print()
        self._Message = self._Message.process()
        print(self._Message)
        print()
        self._Message = DHCP_Release(self._Message)
        print(self._Message)
        self._Message = self._Message.process()'''
    
    #Metoda pentru setarea mesajului curent
    def setMessage(self, mess: message):
        self._Message = mess

#Functie pentru citirea de la tastatura a unor valori ce vor introduce in "coada" mesaje de tip DHCPDISCOVER, DHCPREQUEST si DHCPDECLINE
#Scopul acestei functii este de a testa comportametul Serverului in punctul curent de dezvoltare
def mesaj(ob: Server):
    
    while True:
        print('Pentru Discover alege 1 ; Pentru Request alege 2 ; Pentru Decline alege 3')
        print('Alege tipul mesajului: \r', end='')
        nr = int(input(''))
        if nr == 1:
            coada.append(DHCP_Discover(ob, 0x1, 0x6, 0x0, generateXID(), 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, generateMAC(), None, None))
        elif nr == 2:
            coada.append(DHCP_Request(ob, 0x1, 0x6, 0x0, generateXID(), 0x0, 0x0, ob.aloca(None), 0x0, ob._ServerIdentifier, 0x0, generateMAC(), None, None))
        elif nr == 3:
            coada.append(DHCP_Decline(ob, 0x1, 0x6, 0x0, generateXID(), 0x0, 0x0, random.randint(ob._firstAddr + 1, ob._lastAddr - 1), 0x0, ob._ServerIdentifier, 0x0, generateMAC(), None, None))
    
if __name__ == '__main__':
 
    obiect: Server = Server()
    
    threading.Thread(target=obiect.afisare).start()

    mesaj(obiect)
