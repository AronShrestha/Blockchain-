from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA
from Crypto import Random
    
def RSA_SessionKeyEncryption(public_key,session_key):
    """
    Encrypt the session key with the public RSA key
    """
    rsa_encrypt = PKCS1_OAEP.new(public_key)
    encrypted_session_key = rsa_encrypt.encrypt(session_key)
    return encrypted_session_key

def AES_DataEncryption(session_key,data):
    """"
    Using AES algorithm to encrypt the data
    """
    block_size  = AES.block_size
    pad = block_size -(len(data)%block_size)
    data += bytes([pad])*pad
    cipher_AES = AES.new(session_key,AES.MODE_CBC,session_key)
    ciphertext = cipher_AES.encrypt(data)
    return ciphertext

def RSA_SessionKeyDecryption(private_key,encrypted_session_key):
    rsa_decrypt = PKCS1_OAEP.new(private_key)
    session_key = rsa_decrypt.decrypt(encrypted_session_key) #regenerating original session key
    return session_key

def AES_DataDryption(session_key,ciphertext):
    cipher_AES = AES.new(session_key,AES.MODE_CBC,session_key)
    plaintext = cipher_AES.decrypt(ciphertext)
    plaintext = plaintext[:-plaintext[-1]]
    return plaintext

def SessionKeyGen():
    """Generates session key"""
    session_key = Random.new().read(AES.block_size)
    return session_key

def RSA_KeyGen(key_length):
    """
    Generates RSA key
    """
    private_key = RSA.generate(key_length)
    public_key = private_key.publickey()
    return private_key,public_key



    
        
        
