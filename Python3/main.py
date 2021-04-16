from cryptography.hazmat.primitives.ciphers import (
    Cipher, algorithms, modes
)
import os
import base64

# 加密方法
def encrypt(plaintext,key,iv):
    encryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv),
    ).encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return (ciphertext, encryptor.tag)

# 解密方法
def decrypt(ciphertext,tag, key,iv):
    decryptor = Cipher(
        algorithms.AES(key),
        modes.GCM(iv, tag),
    ).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# 常规加密解密测试
def testCommon():
    data = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm"	    #待加密数据
    key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="  #秘钥(Base64格式)
    iv64 = "j2tauE9NI5aBvxso";
    #iv = base64.b64decode(iv64) #固定向量，用于测试
    iv = os.urandom(12);        #随机向量生成

    ciphertext, tag = encrypt(data.encode('utf-8'),base64.b64decode(key),iv)
    print("cipher64: " + base64.b64encode(ciphertext).decode())
    print("tag64: " + base64.b64encode(tag).decode())
    plaintext = decrypt(ciphertext,tag,base64.b64decode(key),iv).decode('utf-8')
    print("plaintext: " + plaintext)


#解密服务器发来的数据
def testDecryptFromServer():
    key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; #秘钥(Base64格式),cp方持有	
            
    cipherTextServer = "S89syga21yniBAlANVllVqYplznwF1YOkk04d4rHBQGata6bDysOsGCGUEgUJ0hdEyVkFBNANXrplMry29B+F9ChfJjDVGUBiMb83qlsKQ+560V4+51TzFxi3kf7IuLfi6Va0H7h5I0=";		#Base64的加密后数据。服务端返回
    iv64 = "j2tauE9NI5aBvxso";		#base64的初始向量，服务端返回

    cipherByteServer = base64.b64decode(cipherTextServer)
    cipher = cipherByteServer[:len(cipherByteServer) - 16]
    tag = cipherByteServer[len(cipherByteServer) - 16:]
    iv = base64.b64decode(iv64);
    plaintext = decrypt(cipher,tag,base64.b64decode(key),iv).decode('utf-8')
    print("plaintext: " + plaintext)

#生成发送给服务器的数据
def testEncryptToServer():
    key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; #秘钥(Base64格式),cp方持有

    data = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm"	    #待加密数据
    #iv64 = "j2tauE9NI5aBvxso";		#base64的初始向量，服务端返回
    #iv = base64.b64decode(iv64)         #固定向量，用于测试
    iv = os.urandom(12);        #随机向量生成,正式使用时务必使用随机向量
    iv64 = base64.b64encode(iv).decode()     #需要传递给服务器的iv base64字符串
    ciphertext, tag = encrypt(data.encode('utf-8'),base64.b64decode(key),iv)
    print("cipher64: " + base64.b64encode(ciphertext).decode())
    print("tag64: " + base64.b64encode(tag).decode())
    cipherByteServer = ciphertext + tag
    cipherTextServer = base64.b64encode(cipherByteServer).decode()      #把cipher和tag拼接起来的最终数据
    print("cipherTextServer: " + cipherTextServer)


print("hello demo-python3")
#testCommon()
#testDecryptFromServer()
testEncryptToServer()
