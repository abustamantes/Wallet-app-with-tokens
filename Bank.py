import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import binascii

student_id = str(1234567)
amount = hex(2000)[2:].zfill(32)


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
    return (plainText, decrypted)

key_wallet = Kwallet(student_id)
print(amount, key_wallet)
enc_text = encryptWallet(amount, key_wallet)

print(enc_text)
key_wa=Kwallet("1234567")
print(decryptWallet(enc_text,key_wa))