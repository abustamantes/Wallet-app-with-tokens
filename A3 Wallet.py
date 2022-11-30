from tkinter import *
import hmac
import hashlib
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto import Random
import binascii
from tkinter import messagebox


class table:
    def __init__(self, wid_t,amount_t,counter_t):
        self.wid_t=wid_t
        self.amount_t=amount_t
        self.counter_t=counter_t
    
    def create_partner(self):
        return (self.wid_t,self.amount_t,self.counter_t)


class Wallet(table):
    x=0
    y=0
    balance=0
    balance_rcv=0
    synch="Your wallet is yet to be synchronized"
    Kwallet=""
    student_id=""
    Kbank="F25D58A0E3E4436EC646B58B1C194C6B505AB1CB6B9DE66C894599222F07B893"
    wid_local=""
    wid_remote=""
    r_wid_local=""
    r_wid_remote=""
    rcv_token=[]
    partners=[]
    partners_wid=[]


    def __init__(self):
        self.root=Tk()
        self.root.title(f"Wallet ID")
        self.root.geometry("520x300")

        messagebox.showinfo('Important','Do not forget to FIRST enter your student ID to run the app')
        self.root.focus_force()

        self.Balance=Label(self.root,text=f"Your balance is: {self.balance}")
        self.Balance.grid(row=1,column=2)

        self.UI1=Label(self.root,text=f"UI 1 (First UI)",fg="blue")
        self.UI1.grid(row=2,column=2)

        self.labeltext0=StringVar()
        self.labeltext0.set("EMD:")
        self.labelDir0=Label(self.root,textvariable=self.labeltext0)
        self.labelDir0.grid(row=3,column=1)
        directory0=StringVar(None)
        self.EMD = Entry(self.root, width=50, bg="white", fg="black",textvariable=directory0)
        self.EMD.grid(row=3,column=2)

        self.Redeem_=Button(self.root,text="Redeem EMD",command=self.Redeem,fg="black", bg="white")
        self.Redeem_.grid(row=3,column=3)

        self.UI2=Label(self.root,text=f"UI 2 (Second UI)",fg="blue")
        self.UI2.grid(row=4,column=2)

        self.labeltext=StringVar()
        self.labeltext.set("My student ID:")
        self.labelDir=Label(self.root,textvariable=self.labeltext)
        self.labelDir.grid(row=5,column=1)
        directory=StringVar(None)
        self.ID = Entry(self.root, width=50, bg="white", fg="black",textvariable=directory)
        self.ID.grid(row=5,column=2)

        self.MyID=Button(self.root,text="Enter your ID",command=self.My_ID,fg="black", bg="white")
        self.MyID.grid(row=5,column=3)

        self.labeltext2=StringVar()
        self.labeltext2.set("Target student ID:")
        self.labelDir2=Label(self.root,textvariable=self.labeltext2)
        self.labelDir2.grid(row=6,column=1)
        directory2=StringVar(None)
        self.ID2 = Entry(self.root, width=50, bg="white", fg="black",textvariable=directory2)
        self.ID2.grid(row=6,column=2)

        self.targetID=Button(self.root,text="Enter target ID",command=self.Target_ID,fg="black", bg="white")
        self.targetID.grid(row=6,column=3)

        self.sync=Button(self.root,text="Synchronize Wallets",command=self.Syn,fg="black", bg="white")
        self.sync.grid(row=7,column=1)
        self.syn1=Label(self.root,text=self.synch)
        self.syn1.grid(row=7,column=2)

        self.UI3=Label(self.root,text=f"UI 3 (Third UI)",fg="blue")
        self.UI3.grid(row=8,column=2)

        self.labeltext3=StringVar()
        self.labeltext3.set("Money to transfer:")
        self.labelDir3=Label(self.root,textvariable=self.labeltext3)
        self.labelDir3.grid(row=9,column=1)
        directory3=StringVar(None)
        self.ID3 = Entry(self.root, width=50, bg="white", fg="black",textvariable=directory3)
        self.ID3.grid(row=9,column=2)      

        self.transfer_token=Button(self.root,text="Generate token",command=self.generate_token,fg="black", bg="white")
        self.transfer_token.grid(row=10,column=1)
        self.transfer_token1=Label(self.root,text=f"Pulse here to get your money token")
        self.transfer_token1.grid(row=10,column=2)

        self.UI4=Label(self.root,text=f"UI 4 (Fourth UI)",fg="blue")
        self.UI4.grid(row=11,column=2)

        self.redeem_token=Button(self.root,text="Redeem Token",command=self.redeem_tk,fg="black", bg="white")
        self.redeem_token.grid(row=12,column=1)
        self.redeem_token1 = Entry(self.root, width=50, bg="white", fg="black")
        self.redeem_token1.grid(row=12,column=2)

        self.root.mainloop()
    
    @staticmethod
    def hexa(val):
         return hex(val)[2:].zfill(32)
         
    @staticmethod
    def encrypt(raw, key):
        plainText = str(raw)
        key = str(key).lower()
        key = bytes.fromhex(key)    
        cipher = AES.new(key, AES.MODE_ECB)
        data = bytes.fromhex(plainText)
        cipherText = cipher.encrypt(data)
        cipherText=cipherText.hex()    
        return cipherText
    
    @staticmethod
    def decrypt_emd(enc, key):
        cipherText = str(enc)
        key = str(key).lower()
        key = bytes.fromhex(key)    
        cipher = AES.new(key, AES.MODE_ECB)
        data = bytes.fromhex(cipherText)
        plainText = cipher.decrypt(data)    
        plainText = plainText.hex()
        decrypted = int(plainText, 16)
        if len(str(decrypted))>=10:
            return 0
        else:
            return decrypted
        

    @staticmethod
    def decrypt_token(enc, key):
        cipherText = str(enc)
        key = str(key).lower()
        key = bytes.fromhex(key)
        cipher = AES.new(key, AES.MODE_ECB)
        data = bytes.fromhex(cipherText)
        plainText = cipher.decrypt(data)
        plainText = plainText.hex()
        return plainText
    
    def Redeem(self):
        if not self.EMD.get() or len(self.EMD.get())!=32:
            print("You have to enter a valid token")
        elif self.student_id.isnumeric()!=True or not self.student_id: 
            print("Enter a valid student ID")
        elif self.EMD.get() not in self.rcv_token:
            self.rcv_token.append(self.EMD.get())
            try:
                self.Kwallet=self.Kwallet_f(self.student_id)
                enc=self.EMD.get()
                #enc=enc.encode('utf-8')
                if self.decrypt_emd(enc,self.Kwallet)!=0:
                    self.balance=self.balance + self.decrypt_emd(enc,self.Kwallet)
                    self.Balance.config(text=f"Your balance is: {self.balance}")
                    self.EMD.delete(0,END)
                else:
                    if self.EMD.get() in self.rcv_token:
                        self.rcv_token.remove(self.EMD.get())
                    print("Your student ID is not valid for this token, or your token has zero dollars")                 
                self.EMD.delete(0,END)
            except:
                self.Balance.config(text=f"Enter your ID or a valid token, balance is {self.balance}")
                print(f"Enter your ID or a valid token, balance is {self.balance}")
                if self.EMD.get() in self.rcv_token:
                    self.rcv_token.remove(self.EMD.get())
                self.EMD.delete(0,END)
        else:
            print("You already redeemed this token!, if this is an error, generate the token again")
            self.EMD.delete(0,END)

    @staticmethod
    def Kwallet_f(val):
        return hashlib.sha256(str(val).encode()).hexdigest()

    def My_ID(self):
        if not self.ID.get() or self.ID.get().isnumeric()!=True:
            print("Introduce a valid student ID")            
        else:
            self.student_id=self.ID.get()
            self.wid_local=self.student_id[-4:]
            print(f"My ID is: {self.wid_local}")
            self.root.title(f"Wallet ID {self.wid_local}")            

    def Target_ID(self):
        if not self.ID2.get() or self.ID2.get().isnumeric()!=True:
            print("Introduce a valid target student ID")            
        else:
            self.wid_remote=self.ID2.get()[-4:]
            print(f"The remote ID is: {self.wid_remote}")

    def Syn(self):
        try:
            com_value=self.hexa(int(self.wid_local))[-8:]+self.hexa(int(self.wid_remote))[-8:]+self.hexa(0)[-8:]+self.hexa(0)[-8:]
            enc_com_value=self.encrypt(com_value,self.Kwallet_f(self.Kbank))        
            self.syn1.config(text="Use the syn token sent to your email")
            print(f"Synchronization token: {enc_com_value}")
        except:
            self.syn1.config(text="Introduce local and remote WID")
            print("Introduce local and remote WID")
    
    @staticmethod
    def decode_hex(val):
        blc = "0x"+val.decode('utf-8');
        return int(blc,0)

    def redeem_tk(self):
        if not self.redeem_token1.get():
            print("You have to enter a token")
        elif self.redeem_token1.get() not in self.rcv_token:
            self.rcv_token.append(self.redeem_token1.get())
            try:
                enc=self.redeem_token1.get()
                #enc=enc.encode('utf-8')
                reception=self.decrypt_token(enc,self.Kwallet_f(self.Kbank))
                #reception=reception.decode('utf-8')
                self.r_wid_remote=reception[:8]
                self.r_wid_local=reception[8:16]
                self.balance_rcv=reception[16:24]
                self.y=reception[24:32]
                #print(reception)
                self.r_wid_remote=self.r_wid_remote.encode('utf-8')
                self.r_wid_local=self.r_wid_local.encode('utf-8')
                self.balance_rcv=self.balance_rcv.encode('utf-8')
                self.y=self.y.encode('utf-8')
                #Obtaining int numbers
                self.r_wid_local=self.decode_hex(self.r_wid_local)
                self.r_wid_remote=self.decode_hex(self.r_wid_remote)
                self.balance_rcv=self.decode_hex(self.balance_rcv)
                self.y=self.decode_hex(self.y)
                #print(self.r_wid_local,self.r_wid_remote,self.balance_rcv,self.y)      
                if str(self.r_wid_local)==self.wid_local and self.y==0:
                    for i in self.partners:
                        self.partners_wid.append(i[0])       
                    partner=table(self.r_wid_remote,self.balance_rcv,self.y)
                    self.partners.append(table.create_partner(partner))
                    self.syn1.config(text=f"You have accepted the sender WID: {self.r_wid_remote}")
                    print(f"You have accepted the sender WID: {self.partners}")
                    #print(self.partners_wid)
                    self.partners_wid=[]
                    self.redeem_token1.delete(0,END)                 
                elif str(self.r_wid_local)==self.wid_local and self.y!=0:
                    for i in self.partners:
                        self.partners_wid.append(i[0])
                    #print(f'table: {self.partners}')
                    #print(f'wid: {self.partners_wid}')
                    if self.r_wid_remote in self.partners_wid:
                        index1=self.partners_wid.index(self.r_wid_remote)
                        tuple1=self.partners[index1]
                        tuple1=list(tuple1)
                        tuple1[2]=tuple1[2]+1
                        self.balance=self.balance+self.balance_rcv 
                        tuple1[1]=tuple1[1]+self.balance_rcv
                        tuple1=tuple(tuple1)
                        self.partners[index1]=tuple1
                        print(self.partners)                        
                        self.Balance.config(text=f"Your current balance is: {self.balance}")
                    else:
                        print("The source wid of this token is not in our tables, you must first redeem the syn token, and then redeem this money token")
                        if self.redeem_token1.get() in self.rcv_token:
                            self.rcv_token.remove(self.redeem_token1.get())
                    self.redeem_token1.delete(0,END)
                else:
                    print("Error: The token is incorrect, the wallets are not synchronized, or the transfer is not for this wallet")
                    if self.redeem_token1.get() in self.rcv_token:
                        self.rcv_token.remove(self.redeem_token1.get())
                    self.redeem_token1.delete(0,END)
            except:
                print("You have to synchronize the sender wallet and introduce your ID")
                if self.redeem_token1.get() in self.rcv_token:
                    self.rcv_token.remove(self.redeem_token1.get())
                self.redeem_token1.delete(0,END)
        else:
            print("You already redeemed this token!")
            self.redeem_token1.delete(0,END)  

  
    def generate_token(self):
        try:
            if self.wid_local!="" and self.wid_remote!="" and self.ID3.get()!="":
                self.x =self.x + 1
                com_value=self.hexa(int(self.wid_local))[-8:]+self.hexa(int(self.wid_remote))[-8:]+self.hexa(int(self.ID3.get()))[-8:]+self.hexa(self.x)[-8:]
                self.balance=self.balance-int(self.ID3.get())
                enc_com_value=self.encrypt(com_value,self.Kwallet_f(self.Kbank))        
                self.transfer_token1.config(text="Use the money token sent to your email")
                self.Balance.config(text=f"Your balance is: {self.balance}")
                print(f"Money token to redeem transfer: {enc_com_value}")
                print(f"Counter: {self.x}")
                messagebox.showinfo('Important','You just generated a money token and your balance has been reduced, the target wallet must redeem the token, otherwise, you will lose that money!')
                self.root.focus_force()
            else:
                self.transfer_token1.config(text="First synchronize wallets and fill mandatory fields")
                print("Synchronize wallets and fill mandatory fields")
        except:
            self.transfer_token1.config(text="First synchronize wallets and fill mandatory fields")

Wallet()