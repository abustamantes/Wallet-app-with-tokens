import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import binascii


amount = hex(5000)[2:].zfill(32)
print(type(amount))


student_id = str(1234567)
def kwallet(val):
    return hashlib.sha256(val.encode("utf-8")).digest()

print(f"we gotta get this: {kwallet(student_id)}")
print(f'TYPE: {type(kwallet(student_id))}')


 
def encrypt(raw, key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(raw.encode('utf-8'))
    encrypted = binascii.hexlify(encrypted)
    iv_enc_text = binascii.hexlify(iv) + encrypted
    iv_enc_text_print = iv_enc_text.decode('utf-8')
    return iv_enc_text_print
    #return (iv_enc_text, iv)

def decrypt(enc, key):
    un_hex_iv = binascii.unhexlify(enc[:32])
    un_hex_emd = binascii.unhexlify(enc[32:])
    cipher = AES.new(key, AES.MODE_CBC, un_hex_iv)
    decrypted = cipher.decrypt(un_hex_emd)
    #print("dec",type(decrypted), decrypted)
    #blc = "0x"+decrypted.decode('utf-8');
    #blc=int(blc,0)
    return decrypted

    #print(int(blc, 0))

print(encrypt(amount,kwallet(student_id)))

print(decrypt(b'b6729d1a58b8ab6dfe89ceeec80f3f4f2222461102486d44381308f20e347dd8fe254c598da0db897c84d0eeddc50f62',kwallet(student_id)))
