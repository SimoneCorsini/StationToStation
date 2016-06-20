# This is Alice (client).

print('Welcome to STS, Alice!')

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

# Le chiavi di Alice sono state generate e salvate con i seguenti metodi.
#from Crypto import Random
#sha = hashlib.sha256()
#random_generator = Random.new().read
#keys = RSA.generate(1024, random_generator)
#file = open('Apriv.pem', 'w')
#file.write(keys.exportKey('PEM'))
#file.close()
#file = open('Apub.pem', 'w')
#file.write(keys.publickey().exportKey('PEM'))
#file.close()

# Read Apriv
key = open('Apriv.pem', 'r').read()
Apriv = RSA.importKey(key)

# Read Bpub
key = open('Bpub.pem', 'r').read()
Bpub = RSA.importKey(key)

# RFC-3526, Chiavi da 2048 bit (618 cifre decimali).
p = int('FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF', 16)
g = 2
Sa = random.randint(1, p-1)
Ta = pow(g, Sa, p)

HOST = ''
PORT = 24069

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
print('Socket created')
print('Connecting to server...')
try:
    client_socket.connect((HOST, PORT))
except socket.error as msg:
    print ('Bind failed. Error code: ' + str(msg[0]) + ' Error message: ' + msg[1]) 
    sys.exit() # Chiude il sistema.
    
print('Socket bind complete. Running authentication protocol...')

# Invio Ta, p e g.
data = str(p) + '\n' + str(g) + '\n' + str(Ta)
client_socket.send(data)

# Ricevo Tb ed Ekb per generare Kt.
data = client_socket.recv(4096)
#print(data)
temp = data.split('EOL')
Tb = int(temp[0])
Ekb = temp[1]
Kt = pow(Tb, Sa, p)
signatureB = decrypt(str(Kt), Ekb)

messageFromB = str(Tb) + str(Ta)
h = SHA512.new(messageFromB)
verifier = PKCS1_v1_5.new(Bpub)
if (verifier.verify(h, signatureB)):
    print("The signature received from the server is authentic.")
    print("Type 'exit' to quit this session.")
    
    # Invio Eka.
    message = str(Ta) + str(Tb)
    h = SHA512.new(message)
    signer = PKCS1_v1_5.new(Apriv)
    signatureA = signer.sign(h)
    Eka = encrypt(str(Kt), signatureA)
    client_socket.send(Eka)
    
    # Scambio di messaggi successivi all'autenticazione.
    send = 0
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
			print("Waiting for Bob's message...");
			messageFromB = client_socket.recv(1024)
			if (messageFromB == 'Authentication failed.'):
				print('Authentication failed.')
				messageFromB = 'exit'
				
			if (messageFromB != 'exit'):
				print('Bob said: ' + decrypt(str(Kt), messageFromB))
				send = 1
			else:
				print('Session terminated by Bob.')
				message = 'exit'
			
else:
    print("The signature received from the server is NOT authentic.")

Sa = None
Kt = None

client_socket.close()
