#import socket
#import sys
host = "172.16.5.32"
port = 8000
from socket import *
s=socket(AF_INET,SOCK_STREAM)

s.bind((host,port))

noOfClientsListening = 1
try:
        s.listen(noOfClientsListening)
        print "Listening to %d number of clients" %noOfClientsListening
except:
        print "Listening error: "
        raise SystemExit()
while 1:

        q,addr=s.accept()
        data = q.recv(1024)
        #print recvFile.read()
        recvFile = open("server1.jpg","wb")
        recvFile.write(data)
        while 1:
                if not data:
                        break
                data=q.recv(1024)
                recvFile.write(data)
        recvFile.close()
        print "transfer complete"
s.close()
