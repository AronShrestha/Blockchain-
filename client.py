import socket 
# import threading
from security import *

def client():
    n= 2048 #number of bitsreceived(should be constant for size of key)
    private_key,public_key = RSA_KeyGen(n)
    client =  socket.socket(socket.AF_INET,socket.SOCK_STREAM)#get instance
    port =  9999
    client.connect(("localhost",port))
    #sending clients public key to server
    client.send(public_key.export_key())
    #receiving the encrypted session key from the server
    enc_session_key = client.recv(n)
    #now decrypting encrypted session key received from server using client private key
    session_key = RSA_SessionKeyDecryption(private_key,enc_session_key)
    print("Press q to quit")
    print("*"*20)
    #Starting messaging from client to server
    request =  bytes(input('Client :'),"utf-8")

    while request.lower().strip() != b'q':
        ciphertext = AES_DataEncryption(session_key,request)
        #sending encrypted text message (cipher text)
        client.send(ciphertext)

        #receiving encrypted message from server
        encrypted_message = client.recv(n)
        if not encrypted_message:
            break
        #encrypted msg converting  to plaintext 
        plaintext = AES_DataDryption(session_key,encrypted_message).decode()

        print("Server : " ,plaintext)
        request = bytes(input('Client : '),"utf-8")
    client.close()

if __name__ == "__main__":
    client()