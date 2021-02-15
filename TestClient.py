import socket
import threading
import pickle
import time

from MsgExample import *

headerSize = 10

mesajPrimit = None

mesajTrimis = None

c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

c.bind((socket.gethostname(), 5050))

c.listen(5)

time.sleep(4)

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.connect((socket.gethostname(), 1234))

def listen():

    global s

    global mesajPrimit
    
    global mesajTrimis
    
    while True:

        full_msg = b''
        new_msg = True
        while True:
            msg = s.recv(8)
            if new_msg:
                print(f"new message length: {int(msg[:headerSize])}")
                msglen = int(msg[:headerSize])
                new_msg = False
                
            full_msg += msg

            if len(full_msg)-headerSize == msglen:
                #print('full message received')
                #print(full_msg[headerSize:])
                mesajPrimit = pickle.loads(full_msg[headerSize:])
                print(mesajPrimit)
                new_msg = True
                full_msg = b''

def speak():
    
    global c
    
    global mesajPrimit
    
    global mesajTrimis
    
    while True:

        clientsocket, address = c.accept()

        print("Connection from", address,"has been established.")

        if mesajPrimit.__class__.__name__ == 'DHCP_Offer':

            mesajTrimis = DHCP_Request(None, 0x1, 0x6, 0x0, 0x21274A1D, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x08002B2ED85E, None, None)

        elif mesajPrimit.__class__.__name__ == 'DHCP_Nak' or mesajPrimit == None:
        
            mesajTrimis = DHCP_Discover(None, 0x1, 0x6, 0x0, 0x21274A1D, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x08002B2ED85E, None, None)
        
        msg = pickle.dumps(mesajTrimis)

        msg = bytes(f'{len(msg):<{headerSize}}', 'utf-8') + msg

        clientsocket.send(msg)
    
               
if __name__ == '__main__':
    threading.Thread(target=listen).start()

    threading.Thread(target=speak).start()
    
    while True:
        if threading.active_count() <= 1:
            break