Ass 1 
import string, random 
 
def caesar_encrypt(txt, s): 
    r="" 
    for c in txt: 
        if c.isalpha(): 
            b=ord('A') if c.isupper() else ord('a') 
            r+=chr((ord(c)-b+s)%26+b) 
        else: 
            r+=c 
    return r 
 
def caesar_decrypt(txt, s): 
    return caesar_encrypt(txt,-s) 
 
 
def mono_encrypt(txt,key): 
    r="" 
    for c in txt: 
        if c.upper() in key: 
            if c.isupper(): 
                r+=key[c] 
            else: 
                r+=key[c.upper()].lower() 
        else: 
            r+=c 
    return r 
 
def mono_decrypt(txt,key): 
    rk={v:k for k,v in key.items()} 
    r="" 
    for c in txt: 
        if c.upper() in rk: 
            if c.isupper(): 
                r+=rk[c] 
            else: 
                r+=rk[c.upper()].lower() 
        else: 
            r+=c 
    return r 
 
 
def vig_encrypt(txt,key): 
    r="" 
    key=key.upper() 
    j=0 
    for c in txt: 
        if c.isalpha(): 
            s=ord(key[j%len(key)])-65 
            if c.isupper(): 
                r+=chr((ord(c)-65+s)%26+65) 
            else: 
                r+=chr((ord(c.upper())-65+s)%26+65).lower() 
            j+=1 
        else: 
            r+=c 
    return r 
 
def vig_decrypt(txt,key): 
    r="" 
    key=key.upper() 
    j=0 
    for c in txt: 
        if c.isalpha(): 
            s=ord(key[j%len(key)])-65 
            if c.isupper(): 
                r+=chr((ord(c)-65-s)%26+65) 
            else: 
                r+=chr((ord(c.upper())-65-s)%26+65).lower() 
            j+=1 
        else: 
            r+=c 
    return r 
 
 
def rail_encrypt(txt,n): 
    if n<=1: return txt 
    f=[[] for _ in range(n)] 
    r=0; d=1 
    for c in txt.replace(" ",""): 
        f[r].append(c) 
        r+=d 
        if r==n-1 or r==0: 
            d*=-1 
    return "".join("".join(r) for r in f) 
 
def rail_decrypt(txt,n): 
    if n<=1: return txt 
    m=[[] for _ in range(n)] 
    r=0; d=1 
    for _ in txt: 
        m[r].append(None) 
        r+=d 
        if r==n-1 or r==0: d*=-1 
    i=0 
    for a in range(n): 
        for b in range(len(m[a])): 
            m[a][b]=txt[i]; i+=1 
    r=0; d=1 
    col=[0]*n 
    out="" 
    for _ in txt: 
        out+=m[r][col[r]] 
        col[r]+=1 
        r+=d 
        if r==n-1 or r==0: d*=-1 
    return out 
 
 
# Vernam 
def ver_gen(l): 
    return [random.randint(0,255) for _ in range(l)] 
 
def ver_encrypt(txt,key): 
    return [ord(txt[i])^key[i] for i in range(len(txt))] 
 
def ver_decrypt(ct,key): 
    return "".join(chr(ct[i]^key[i]) for i in range(len(ct))) 
 
 
# ========= One Time Pad (OTP) ========== 
def otp_gen(l): 
    return [random.randint(0,255) for _ in range(l)] 
 
def otp_encrypt(txt, key): 
    return [ord(txt[i]) ^ key[i] for i in range(len(txt))] 
 
def otp_decrypt(ct, key): 
    return "".join(chr(ct[i] ^ key[i]) for i in range(len(ct))) 
 
 
# MENU 
while True: 
    print("\n1 Caesar") 
    print("2 Monoalphabetic") 
    print("3 Polyalphabetic (Vigenere)") 
    print("4 Rail Fence") 
    print("5 Vernam") 
    print("6 One Time Pad (OTP)") 
    print("7 Exit") 
    ch=int(input("Choice: ")) 
     
    if ch==1: 
        p=input("Text: ") 
        s=int(input("Shift: ")) 
        e=caesar_encrypt(p,s) 
        print("Encrypted:",e) 
        print("Decrypted:",caesar_decrypt(e,s)) 
 
    elif ch==2: 
        key={} 
        alpha=list(string.ascii_uppercase) 
        sub=alpha.copy() 
        random.shuffle(sub) 
        for i in range(26): 
            key[alpha[i]]=sub[i] 
        p=input("Text: ") 
        e=mono_encrypt(p,key) 
        print("Key:",key) 
        print("Encrypted:",e) 
        print("Decrypted:",mono_decrypt(e,key)) 
 
    elif ch==3: 
        p=input("Text: ") 
        k=input("Key: ") 
        e=vig_encrypt(p,k) 
        print("Encrypted:",e) 
        print("Decrypted:",vig_decrypt(e,k)) 
 
    elif ch==4: 
        p=input("Text: ") 
        r=int(input("Rails: ")) 
        e=rail_encrypt(p,r) 
        print("Encrypted:",e) 
        print("Decrypted:",rail_decrypt(e,r)) 
 
    elif ch==5: 
        p=input("Text: ") 
        key=ver_gen(len(p)) 
        e=ver_encrypt(p,key) 
        print("Key:",key) 
        print("Encrypted:",e) 
        print("Decrypted:",ver_decrypt(e,key)) 
 
    elif ch==6: 
        p=input("Text: ") 
        key=otp_gen(len(p)) 
        e=otp_encrypt(p,key) 
        print("OTP Key:",key) 
        print("Encrypted:",e) 
        print("Decrypted:",otp_decrypt(e,key)) 
 
    elif ch==7: 
        break 
 
    else: 
        print("Invalid") 
 
ASS 2 
import base64 
 
def enc_bytes(msg: str, key: int) -> bytes: 
    key &= 0xFF 
    pt = msg.encode('utf-8') 
    ct = bytearray() 
    for b in pt: 
        x = ((b ^ key) + key) & 0xFF 
        ct.append(x) 
    return bytes(ct) 
 
def dec_bytes(ct: bytes, key: int) -> str: 
    key &= 0xFF 
    pt = bytearray() 
    for b in ct: 
        x = ((b - key) & 0xFF) ^ key 
        pt.append(x) 
    return pt.decode('utf-8', errors='strict') 
 
 
def menu(): 
    while True: 
        print("\n======================") 
        print(" Custom Crypto Tool ") 
        print("======================") 
        print("1. Encrypt") 
        print("2. Decrypt") 
        print("3. Exit") 
 
        choice = input("Enter choice: ").strip() 
 
        if choice == "1": 
            msg = input("Message: ") 
            key = int(input("Key (0–255): ")) 
            ct = enc_bytes(msg, key) 
            ct_b64 = base64.urlsafe_b64encode(ct).decode('ascii') 
            print("\nEncrypted (Base64):", ct_b64) 
 
        elif choice == "2": 
            ct_b64 = input("Encrypted (Base64): ") 
            key = int(input("Key (0–255): ")) 
            try: 
                ct = base64.urlsafe_b64decode(ct_b64.encode('ascii')) 
                pt = dec_bytes(ct, key) 
                print("\nDecrypted:", pt) 
            except: 
                print("\nDecryption failed!") 
 
        elif choice == "3": 
            print("Goodbye!") 
            break 
 
        else: 
            print("Invalid option!") 
 
 
if __name__ == "__main__": 
    menu() 
 
ass 4 
def mod_exp(b,e,m): 
    return pow(b,e,m) 
 
p=int(input("Enter prime p: ")) 
g=int(input("Enter generator g: ")) 
a=int(input("Enter A's private key: ")) 
b=int(input("Enter B's private key: ")) 
c=int(input("Enter C's private key: ")) 
 
A_pub=mod_exp(g,a,p) 
B_pub=mod_exp(g,b,p) 
C_pub=mod_exp(g,c,p) 
 
while True: 
    print("\n1 Exchange Public Keys between A and B") 
    print("2 Perform Man-In-The-Middle Attack by C") 
    print("3 Exit") 
    choice=input("Choice: ") 
    if choice=="1": 
        print("A's Public Key:",A_pub) 
        print("B's Public Key:",B_pub) 
        S_A=mod_exp(B_pub,a,p) 
        S_B=mod_exp(A_pub,b,p) 
        print("A computes shared secret:",S_A) 
        print("B computes shared secret:",S_B) 
        if S_A==S_B: 
            print("Secure communication established.") 
        else: 
            print("Shared secrets do not match!") 
    elif choice=="2": 
        print("A's Public Key (sent):",A_pub) 
        print("B's Public Key (sent):",B_pub) 
        print("C intercepts and sends its Public Key to both parties:",C_pub) 
        S_A=mod_exp(C_pub,a,p) 
        S_B=mod_exp(C_pub,b,p) 
        print("A computes shared secret with C:",S_A) 
        print("B computes shared secret with C:",S_B) 
        S_C_A=mod_exp(A_pub,c,p) 
        S_C_B=mod_exp(B_pub,c,p) 
        print("C computes shared secret with A:",S_C_A) 
        print("C computes shared secret with B:",S_C_B) 
        if S_A==S_C_A and S_B==S_C_B: 
            print("Man-In-The-Middle attack successful. C can intercept and modify messages.") 
        else: 
            print("MITM attack failed!") 
    elif choice=="3": 
        break 
    else: 
        print("Invalid option") 
 
ASS 5 
def L(x,n): 
    return ((x<<n)&0xffffffff)|((x&0xffffffff)>>(32-n)) 
 
def sha1(m): 
    h0=0x67452301 
    h1=0xEFCDAB89 
    h2=0x98BADCFE 
    h3=0x10325476 
    h4=0xC3D2E1F0 
    ml=len(m)*8 
    m=m.encode() 
    m+=b'\x80' 
    while ((len(m)*8)%512)!=448: 
        m+=b'\x00' 
    m+=ml.to_bytes(8,'big') 
    for i in range(0,len(m),64): 
        chunk=m[i:i+64] 
        w=[0]*80 
        for j in range(16): 
            w[j]=int.from_bytes(chunk[j*4:j*4+4],'big') 
        for j in range(16,80): 
            w[j]=L(w[j-3]^w[j-8]^w[j-14]^w[j-16],1) 
        a=h0 
        b=h1 
        c=h2 
        d=h3 
        e=h4 
        for j in range(80): 
            if j<20: 
                f=(b&c)|((~b)&d) 
                k=0x5A827999 
            elif j<40: 
                f=b^c^d 
                k=0x6ED9EBA1 
            elif j<60: 
                f=(b&c)|(b&d)|(c&d) 
                k=0x8F1BBCDC 
            else: 
                f=b^c^d 
                k=0xCA62C1D6 
            t=(L(a,5)+f+e+k+w[j])&0xffffffff 
            e=d 
            d=c 
            c=L(b,30) 
            b=a 
            a=t 
        h0=(h0+a)&0xffffffff 
        h1=(h1+b)&0xffffffff 
        h2=(h2+c)&0xffffffff 
        h3=(h3+d)&0xffffffff 
        h4=(h4+e)&0xffffffff 
    return "".join(f"{x:08X}" for x in (h0,h1,h2,h3,h4)) 
 
msg=input("Enter the message to be hashed: ") 
h=sha1(msg) 
print("\nSHA-1 Hash of the message is:",h) 
print("\nFirst 8 characters of the hash are:",h[:8]) 
 
ASS 6 
import random,hashlib 
 
def is_prime(n): 
if n<=1:return False 
for i in range(2,int(n**0.5)+1): 
if n%i==0:return False 
return True 
def gcd(a,b): 
while b!=0:a,b=b,a%b 
return a 
def mod_inverse(a,m): 
for i in range(1,m): 
if (a*i)%m==1:return i 
return None 
def generate_keypair(): 
p=q=1 
while not is_prime(p):p=random.randint(100,1000) 
while (not is_prime(q)) or p==q:q=random.randint(100,1000) 
n=p*q 
phi=(p-1)*(q-1) 
e=random.randint(1,phi) 
while gcd(e,phi)!=1:e=random.randint(1,phi) 
d=mod_inverse(e,phi) 
return (e,n),(d,n) 
def rsa_encrypt(msg,key): 
e,n=key 
return [pow(ord(c),e,n) for c in msg] 
def rsa_decrypt(enc,key): 
d,n=key 
return ''.join(chr(pow(c,d,n)) for c in enc) 
def sign(msg,priv): 
h=hashlib.sha256(msg.encode()).hexdigest() 
return rsa_encrypt(h,priv) 
def verify(msg,sig,pub): 
h=hashlib.sha256(msg.encode()).hexdigest() 
return rsa_decrypt(sig,pub)==h 
pubX,privX=generate_keypair() 
pubY,privY=generate_keypair() 
print("Keys Generated") 
print("X Public:",pubX) 
print("X Private:",privX) 
print("Y Public:",pubY) 
print("Y Private:",privY) 
msg=input("X Enter Message: ") 
cipher=rsa_encrypt(msg,pubY) 
sig=sign(msg,privX) 
print("\nSent Cipher:",cipher) 
print("Signature:",sig) 
recv=rsa_decrypt(cipher,privY) 
ok=verify(recv,sig,pubX) 
print("\nY Received:",recv) 
if ok:print("Signature Valid. Integrity + Non-repudiation OK.") 
else:print("Signature Invalid.") 
ASS 8 
from PIL import Image 
import numpy as np 
import random 
def encrypt_image(input_path, output_path, key): 
img = Image.open(input_path) 
arr = np.array(img) 
f
 lat = arr.flatten() 
f
 lat = np.array([b ^ key for b in flat], dtype=np.uint8) 
random.seed(key) 
idx = list(range(len(flat))) 
random.shuffle(idx) 
encrypted = flat[idx] 
encrypted = encrypted.reshape(arr.shape) 
enc_img = Image.fromarray(encrypted) 
enc_img.save(output_path) 
print(f"[OK] Strongly Encrypted → {output_path}") 
def decrypt_image(input_path, output_path, key): 
img = Image.open(input_path) 
arr = np.array(img) 
f
 lat = arr.flatten() 
random.seed(key) 
idx = list(range(len(flat))) 
random.shuffle(idx) 
    inverse = [0] * len(flat) 
    for i, j in enumerate(idx): 
        inverse[j] = i 
    flat = flat[inverse] 
    flat = np.array([b ^ key for b in flat], dtype=np.uint8) 
    restored = flat.reshape(arr.shape) 
    dec_img = Image.fromarray(restored) 
    dec_img.save(output_path) 
    print(f"[OK] Decrypted → {output_path}") 
 
if __name__ == "__main__": 
    while True: 
        print("\n====== IMAGE SECURITY SYSTEM ======") 
        print("1. Encrypt Image") 
        print("2. Decrypt Image") 
        print("3. Exit") 
 
        ch = input("Enter choice: ") 
 
        if ch == "1": 
            inp = input("Input image: ") 
            out = input("Encrypted output: ") 
            key = int(input("Key: ")) 
            encrypt_image(inp, out, key) 
 
        elif ch == "2": 
            inp = input("Encrypted image: ") 
            out = input("Decrypted output: ") 
            key = int(input("Key: ")) 
            decrypt_image(inp, out, key) 
 
elif ch == "3": 
print("Goodbye.") 
break 
else: 
print("Invalid choice.") 
