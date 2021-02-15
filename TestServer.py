import socket
import threading
import pickle
import time

from MsgExample import *

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

s.bind((socket.gethostname(), 1234))

s.listen(5)

time.sleep(5)

c = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

c.connect((socket.gethostname(), 5050))

headerSize = 10

mesajPrimit = None

mesajTrimis = None

def listen():
    
    global c
    
    global mesajPrimit
    
    global mesajTrimis
    
    while True:

        full_msg = b''
        new_msg = True
        while True:
            msg = c.recv(8)
            if new_msg:
                print(f"new message length: {int(msg[:headerSize])}")
                msglen = int(msg[:headerSize])
                new_msg = False
                
            full_msg += msg

            if len(full_msg)-headerSize == msglen:
                #print('full message received')
                #print(full_msg[headerSize:])
                mesajPrimit = pickle.loads(full_msg[headerSize:])
                #print(mesajPrimit)
                new_msg = True
                full_msg = b''


def speak():

    global s

    global mesajPrimit
    
    global mesajTrimis

    while True:

        clientsocket, address = s.accept()

        print("Connection from", address,"has been established.")

        if mesajPrimit.__class__.__name__ == 'DHCP_Discover':

            print('da\r',end='')
    
            mesajTrimis = DHCP_Offer(None, 0x1, 0x6, 0x0, 0x21274A1D, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x08002B2ED85E, None, None)

        elif mesajPrimit.__class__.__name__ == 'DHCP_Request':
            
            mesajTrimis = DHCP_Ack(None, 0x1, 0x6, 0x0, 0x21274A1D, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x08002B2ED85E, None, None)

            print('da2\r',end='')

        else:
            print('da3\r',end='')

        msg = pickle.dumps(mesajTrimis)

        msg = bytes(f'{len(msg):<{headerSize}}', 'utf-8') + msg

        clientsocket.send(msg)
        
if __name__ == '__main__':

    threading.Thread(target=speak).start()

    threading.Thread(target=listen).start()
    
    while True:
        if threading.active_count() <= 1:
            break