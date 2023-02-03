import socket 
# import threading
from security import *

def server():
    session_key = SessionKeyGen()
    server = socket.socket(socket.AF_INET,socket.SOCK_STREAM)#get instance
    port = 9999
    server.bind(("localhost",port))#bind host address and port together
    server.listen(1)#configure how many client the server can lisen simultaneously default 1
    print("************************* Waiting for Client to Connect  ********************************")
    conn,addrs = server.accept()#accept new connection
    print("Connection from : "+str(addrs))
    n= 2048 #number of bitsreceived(should be constant for size of key)
    #getting public key from client
    client_public_key = RSA.import_key(conn.recv(n)) #here conn is our socket
    enc_session_key = RSA_SessionKeyEncryption(client_public_key,session_key)
    conn.send(bytes(enc_session_key))
    print("Press q to quit")
    print("*"*20)

    while True:
        #receiving message from client in encrypted form 
        encrypted_message = conn.recv(n)
        if not encrypted_message:
            break
        plaintext = AES_DataDryption(session_key,encrypted_message)
        plaintext = plaintext.decode()
        print("Client : ",str(plaintext))

        #sending message to client
        response = bytes(input("Server : "),"utf-8")
        if response.lower().strip() ==b'q':
            break
        ciphertext = AES_DataEncryption(session_key,response)
        conn.send(ciphertext)
    conn.close()
    
if __name__ == "__main__":
    server()
    



