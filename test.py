import unittest
from security import *

session_key =  SessionKeyGen()
private_key , public_key = RSA_KeyGen(2048)

# Encrypt the session key with the public RSA key
encrypted_session_key = RSA_SessionKeyEncryption(public_key,session_key)
client_data=b"Client is responding !"
validate_client_data_string = "Client is responding !"
server_data = b"Server is waiting for client !!!!!!!"
validate_server_data_string = "Server is waiting for client !!!!!!!"

#Unit testing
class TestCryptography(unittest.TestCase):
    def test_for_server(self):
        self.client_public_key = public_key
        self.ciphertext = AES_DataEncryption(session_key,client_data)
        self.plaintext =  AES_DataDryption(session_key,self.ciphertext)
        self.plaintext = self.plaintext.decode()
        self.assertEqual(str(self.plaintext),validate_client_data_string)
    
    def test_for_client(self):
        self.private_key = private_key
        self.enc_session_key = encrypted_session_key
        self.sessionkey = RSA_SessionKeyDecryption(private_key,self.enc_session_key)
        self.ciphertext = AES_DataEncryption(self.sessionkey,server_data)
        self.plaintext = AES_DataDryption(session_key,self.ciphertext).decode()
     
        self.assertEqual(str(self.plaintext),validate_server_data_string)

if __name__=='__main__':
    unittest.main()
