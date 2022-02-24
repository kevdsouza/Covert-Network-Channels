#!/usr/bin/env python
import sys
import random
import  hashlib
import base64
import string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import msgdef_pb2 as msg
from scapy.all import *

response = msg.ExpressionResponse()

def realPacketCrafter(destIP, destPort, letter):
    #Convert ASCII letter to decimal value
    letter = ord(letter)
    destPort = int(destPort)
    #Note that the time to live is set for 188 seconds - this is the key that the server will look for.
    craftedPacket = IP(src=getSpoofedIP(), dst=destIP, ttl=188)/TCP(sport=letter, dport=destPort, flags="SA")
    return craftedPacket

def fakePacketCrafter(destIP, destPort):
    destPort = int(destPort)
    #Difference between fake and real packet is the (recommended) TTL of 64 and no data of interest being sent.
    craftedPacket = IP(src=getSpoofedIP(), dst=destIP, ttl=64)/TCP(dport=destPort, flags="SA")
    return craftedPacket

def getSpoofedIP():
  #getfqdn used in place of gethostname since some systems return 127.0.0.1
  ipAddress = socket.gethostbyname(socket.getfqdn())
  #ipAddress = socket.gethostbyname(socket.gethostname())
  #Split the different IP sections into their own variables for manipulation
  ip1, ip2, ip3, ip4 = ipAddress.split('.')
  #Choose a random number between 5 and 30 to use as the spoofed source IP
  #Convert randomized number into a string in order to concatenate it.
  ip4 = str(random.randint(5,30))
  ipAddress = ip1 + "." + ip2 + "." + ip3 + "." + ip4
  return ipAddress

def encryptMessage(message):
  keyFile = open("rsa.pub", 'rb')
  keyValue = keyFile.read()
  pubKey = RSA.import_key(keyValue)
  messageEncryptor = PKCS1_OAEP.new(pubKey)
  encryptedMessage = messageEncryptor.encrypt(message.encode())
  return encryptedMessage

def msgHash(encryptedMessage):
  m = hashlib.sha512()
  m.update(encryptedMessage)
  return m.digest()

#Main fuction
if __name__ == "__main__":
  destinationIP = input("Enter the server's IP address: ")
  destinationPort = input("Enter your desired destination port (leave it blank if you wish to have it randomized): ")
  #If the user didn't choose a destination port, randomize on between 1000 and 8505
  if destinationPort == "":
    destinationPort = random.randint(1000,8505)
  #In a while loop in case the user wants to send multiple messages.
  while True:
    #Input from the user of what message data to send covertly over to the server
    data = input("Enter message to covertly send to server: ")
    data += "\n"
    print ("Sending message to server: " + data)
    response.encrypt = encryptMessage(data)
    response.hash = msgHash(response.encrypt)
    response_string = response.SerializeToString()
    response_string = base64.b64encode(response_string)
    responseLength = str(len(response_string.decode()))
   
    letterList = []
    for letter in responseLength:
      letterList.append(letter)
    letterList.append("?")
    #Move all the data into a list for later manipulation and use.
    for letter in response_string.decode():
        letterList.append(letter)
    letterList.append("\n")
    boolCheck = 1
    while (boolCheck):
        #Randomize the packet send interval so it's not so uniform.
        #time.sleep(random.randint(1,5))
        #Randomizer to lower detectability by sending useless packets between actual crafted data packet
        randNum = random.randint(1,2)
        #If the random number equals 2, send the real packet, else send a fake packet.
        if randNum == 2:
            #If the list is empty, flip the checker value and get out of the while loop.
            if len(letterList) == 0:
                boolCheck = 0
                print ("Message successfully sent to server.")
            #If the list is not empty, send the crafted packet
            else:
                #Remove the first item in the list and assign the value to letter.
                letter = letterList.pop(0)
                packet = realPacketCrafter(destinationIP, destinationPort, letter)
                send(packet, verbose=False)
        #If the list is empty, flip the checker value and get out of the while loop.
        elif len(letterList) == 0:
              boolCheck = 0
              print ("Message successfully sent to server.")
        else:
            packet = fakePacketCrafter(destinationIP, destinationPort)
            send(packet, verbose=False)