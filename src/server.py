# This is Bob (server).

print('Welcome to STS, Bob!')

import sys
import math
import socket
import random
import hashlib
from Crypto.Hash import SHA512
from Crypto.Random import random
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from simplecrypt import encrypt, decrypt

# Le chiavi di Bob sono state generate e salvate con i seguenti metodi.
#from Crypto import Random
#sha = hashlib.sha256()
#random_generator = Random.new().read
#keys = RSA.generate(1024, random_generator)

#file = open('Bpriv.pem', 'w')
#file.write(keys.exportKey('PEM'))
#file.close()
#file = open('Bpub.pem', 'w')
#file.write(keys.publickey().exportKey('PEM'))
#file.close()

# Read Bpriv
key = open('Bpriv.pem', 'r').read()
Bpriv = RSA.importKey(key)

# Read Apub
key = open('Apub.pem', 'r').read()
Apub = RSA.importKey(key)

HOST = '' # 'localhost'.
PORT = 24069 # Porta arbitraria.

# Il primo parametro dice che usiamo un dominio IPv4.
# Il secondo parametro ci dice che usiamo la connessione TCP.
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('Socket created')

try:
    server_socket.bind((HOST, PORT))
except socket.error as msg:
    print ('Bind failed. Error code: ' + str(msg[0]) + ' Error message: ' + msg[1]) 
    sys.exit() # Chiude il sistema.

print('Socket bind complete')
server_socket.listen(5)
print('Socket now listening')

# Accetto la connessione del client.
(client_socket, address) = server_socket.accept()    
print('Got connection from client ' + address[0] + '. Running authentication protocol...')

# Ricevo Ta, p e g per generare Kt.
data = client_socket.recv(4096)
temp = data.split('\n')
p = int(temp[0])
g = int(temp[1])
Ta = int(temp[2])
Sb = random.randint(1, p-1)
Tb = pow(g, Sb, p)
Kt = pow(Ta, Sb, p)

# Invio Tb ed Ekb.
message = str(Tb) + str(Ta)
h = SHA512.new(message)
signer = PKCS1_v1_5.new(Bpriv)
signatureB = signer.sign(h)
Ekb = encrypt(str(Kt), signatureB)
data = str(Tb) + 'EOL' + Ekb
client_socket.send(data)

# Ricevo Eka.
Eka = client_socket.recv(1024)
if (Eka != ''):
	signatureA = decrypt(str(Kt), Eka)
	messageFromA = str(Ta) + str(Tb)
	h = SHA512.new(messageFromA)
	verifier = PKCS1_v1_5.new(Apub)
	if (verifier.verify(h, signatureA)):
		print("The signature received from the client is authentic.")
		print("Type 'exit' to quit this session.")
		
		# Scambio di messaggi successivi all'autenticazione.
		send = 1
		while(message != 'exit'):
			if (send == 1):
				message = raw_input('Your message: ')
				if (message == 'exit'):
					print('Session terminated.')
					client_socket.send(message)
				else:
					encrypted = encrypt(str(Kt), message)
					client_socket.send(encrypted)
					print('Message sent successfully.');
					send = 0
			elif (send == 0):
				print("Waiting for Alice's message...")
				messageFromA = client_socket.recv(1024)
				if (messageFromA != 'exit'):
					print('Alice said: ' + decrypt(str(Kt), messageFromA))
					send = 1
				else:
					print('Session terminated by Alice.')
					message = 'exit'
			
	else:
		print("The signature received from the client is NOT authentic.")
		client_socket.send("Authentication failed.")
else:
	print("Authentication failed.")

Sb = None
Kt = None

client_socket.close()
server_socket.close()
