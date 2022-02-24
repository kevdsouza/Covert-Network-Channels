
#!/usr/bin/env python
from logging import error
from re import L
import sys
import  hashlib
import base64
import string
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii
import msgdef_pb2 as msg
from scapy.all import *
# If the packet is TCP and with the key TTL of 188, then grab the secret message.

response = msg.ExpressionResponse()
message = ""

def getMessage(packet):
	global response, message
	try:
		ttl = packet[IP].ttl
		if ttl == 188:
			#count=count+1
			#Pull the data that was hidden in the source port
			letter = packet['TCP'].sport
			if chr(letter) != "\n":
				message += chr(letter)
			else:
				length = int(msgLen(message))
				decodedMessage = message_recv(message,length)
				decodedMessage = base64.b64decode(decodedMessage)
				response.ParseFromString(decodedMessage)
				if response.hash == msgHash(response.encrypt):
					decryptMessage(response.encrypt)

	except IndexError:
		pass

def msgLen(message):
	for i in range (0,len(message)):
		if message[i] == "?":
			length = message[0:i]
			return length

def message_recv(message,length):
	recv_data_length = len(message)-int(length)
	return message[recv_data_length:]

#Subtract 8505 to the ASCII value in order to decrypt the "real" ASCII character
def decryptMessage(message):
	keyFile = open("rsa_priv.pem", 'rb')
	data = keyFile.read()
	privKey = RSA.import_key(data)
	messageDecryptor = PKCS1_OAEP.new(privKey)
	decryptedMessage = messageDecryptor.decrypt(message)
	print("Received message: "+decryptedMessage.decode())

def msgHash(encryptedMessage):
	m = hashlib.sha512()
	m.update(encryptedMessage)
	return m.digest()
	# Main program
if __name__ == "__main__":
	sniff(filter="tcp", prn=getMessage)