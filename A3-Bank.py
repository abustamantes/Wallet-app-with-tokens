import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import binascii

student_id = str(input("Introduce your student ID: "))
amount=int(input("How much money do you need: "))
amount = hex(amount)[2:].zfill(32)


def Kwallet(seed):
    return hashlib.sha256(str(seed).encode()).hexdigest()


def encryptWallet(raw, key):
    plainText = str(raw)
    key = str(key).lower()
    key = bytes.fromhex(key)    
    cipher = AES.new(key, AES.MODE_ECB)
    data = bytes.fromhex(plainText)
    cipherText = cipher.encrypt(data)
    cipherText=cipherText.hex()    
    return cipherText

def decryptWallet(enc, key):
    cipherText = str(enc)
    key = str(key).lower()
    key = bytes.fromhex(key)    
    cipher = AES.new(key, AES.MODE_ECB)
    data = bytes.fromhex(cipherText)
    plainText = cipher.decrypt(data)    
    plainText = plainText.hex()
    decrypted = int(plainText, 16)
    return ("The plaintext:",plainText, "Money decrypted:", decrypted)

key_wallet = Kwallet(student_id)
enc_text = encryptWallet(amount, key_wallet)
print("\n")
print(f'Use this EMD token to collect your money: {enc_text}')
print(decryptWallet(enc_text,key_wallet))