package main

import (
    "crypto/aes"
    "crypto/cipher"
    "crypto/rand"
    //"encoding/hex"
    "fmt"
    "io"
	"encoding/base64"
)
/*
AES 256 GCM 加密解密算法
算法是对称加密算法，秘钥是256位，每次加密需要生成一个12位字节的随机向量iv，随机向量参与加密计算
加密后得到和原始数据同样字节长度的密文ciphertext和16位的数据验证码tag，两者拼接后得到最终密文
最终密文进行Base64编码得到最终密文，随机向量iv也进行Base64编码，一起发给接收端
*/

//加密算法
func encrypt(plainText []byte,key []byte,iv []byte) (cipherByte []byte, err error){
	block, err1 := aes.NewCipher(key)
    if err1 != nil {
        return []byte{}, err
    }
	
	aesgcm, err2 := cipher.NewGCM(block)
    if err2 != nil {
        return []byte{}, err
    }
	
	cipherByte = aesgcm.Seal(nil, iv, plainText, nil)
	fmt.Println("cipherText:	" ,base64.StdEncoding.EncodeToString(cipherByte))
	return cipherByte, nil
}


func decrypt(cipherText []byte,key []byte,iv []byte) (cipherByte []byte, err error){
	block, err1 := aes.NewCipher(key)
    if err1 != nil {
        return []byte{}, err1
    }
	
	aesgcm, err2 := cipher.NewGCM(block)
    if err2 != nil {
        return []byte{}, err2
	}
	
	plainByte, err3 := aesgcm.Open(nil, iv, cipherText, nil)
    if err3 != nil {
        return nil, err3
	}
    plainText := string(plainByte)
	fmt.Println("plainText:	" ,plainText)
	return cipherByte, nil
}



// 加密解密测试
func testCommon() {
	data := "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";		//待加密数据
	key := "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; 	//秘钥(Base64格式)
	keyByte, err1 := base64.StdEncoding.DecodeString(key);
	if err1 != nil {
		fmt.Println(err1)
	}
	
	iv64 := "j2tauE9NI5aBvxso";		//固定向量
	iv,err2 := base64.StdEncoding.DecodeString(iv64);
	if err2 != nil {
		fmt.Println(err2)
	}
	// 随机向量生成方式
	ivRandom := make([]byte, 12)
    if _, err3 := io.ReadFull(rand.Reader, ivRandom); err3 != nil {
		fmt.Println(err3)
        return
    }
	
	cipherByte,err4 := encrypt([]byte(data), keyByte, iv);
	if err4 != nil {
		fmt.Println(err4)
	}
	
	decrypt(cipherByte, keyByte, iv);
	
}

//解密服务器发来的数据
func testDecryptFromServer(){
	key := "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; 	//秘钥(Base64格式)
	cipherTextServer := "S89syga21yniBAlANVllVqYplznwF1YOkk04d4rHBQGata6bDysOsGCGUEgUJ0hdEyVkFBNANXrplMry29B+F9ChfJjDVGUBiMb83qlsKQ+560V4+51TzFxi3kf7IuLfi6Va0H7h5I0=";       //Base64的加密后数据。服务端返回
	iv64 := "j2tauE9NI5aBvxso";		//base64的初始向量，服务端返回

	keyByte, _ := base64.StdEncoding.DecodeString(key);
	cipherByte, _ := base64.StdEncoding.DecodeString(cipherTextServer);
	iv, _ := base64.StdEncoding.DecodeString(iv64);
	decrypt(cipherByte, keyByte, iv);

}

// 生成发送给服务器的数据
func testEncryptToServer(){
	key := "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; 	//秘钥(Base64格式)
	data := "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";		//待加密数据

	keyByte, _ := base64.StdEncoding.DecodeString(key);
	iv := make([]byte, 12)
	io.ReadFull(rand.Reader, iv)
	iv64 := base64.StdEncoding.EncodeToString(iv)		//随机向量，要和加密后的数据一起传到服务器
	fmt.Println("iv64:	" ,iv64)
	cipherByte,_ := encrypt([]byte(data), keyByte, iv);		
	 base64.StdEncoding.EncodeToString(cipherByte)	//加密得到的数据，要编码成base64再传
}

func main() {
    fmt.Println("hello go-aes-gcm")
	//testCommon()
	//testDecryptFromServer()
	testEncryptToServer()
}