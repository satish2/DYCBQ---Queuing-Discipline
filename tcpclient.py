#client code
#import socket
import sys
import os

host = "172.16.5.32"
port = 8000

from socket import *
s= socket(AF_INET,SOCK_STREAM)

try:
        s.connect((host,port))
        print "Connected to server on port %d" %port
except socket.error as msg:
        print "Couldn't connect to server" + str(msg[0]) + "Message: " + msg[1]
        sys.exit()

#sendDataToServer=raw_input("Enter data tp be sent...:")
file = open("1.jog","rb")
#print file.tell()
#print file.read().rstrip("\n")
#print file.read().rstrip("\n")
#print file.tell()
file.seek(0)
#s.send(str(os.path.getsize("send.txt")))
#print str(os.path.getsize("send.jpg"))
bytesToSend = file.read(1024)
#print bytesToSend.rstrip("\n")
y = len(str(file))
#print y
#s.send(str(file))
#ackVar = s.recv(1024)
#print ackVar
s.send(bytesToSend)
x = len(bytesToSend)
#print x
while bytesToSend != "":
        bytesToSend = file.read(1024)
        s.send(bytesToSend)
file.close()
#s.send(file.read())
s.close()



