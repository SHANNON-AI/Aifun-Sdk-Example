/// AES 256 GCM 加密解密算法，
// 算法是对称加密算法，秘钥是256位，每次加密需要生成一个12位字节的随机向量iv，随机向量参与加密计算
// 加密后得到和原始数据同样字节长度的密文ciphertext和16位的数据验证码tag，
// ciphertext 和 tag 以字节的方式拼接，然后进行Base64编码得到最终密文，随机向量iv也进行Base64编码，一起发给接收端

const buffer = require('buffer');
const crypto = require('crypto');

const aes256gcm = (key) => {
    const ALGO = 'aes-256-gcm';
  
    // encrypt returns base64-encoded ciphertext
    const encrypt = (str,iv) => {
      // Hint: the `iv` should be unique (but not necessarily random).
      // `randomBytes` here are (relatively) slow but convenient for
      // demonstration.
      //const iv = Buffer.from(crypto.randomBytes(16), 'utf8');
      const cipher = crypto.createCipheriv(ALGO, key, iv);
  
      // Hint: Larger inputs (it's GCM, after all!) should use the stream API
      let enc = cipher.update(str, 'utf8', 'base64');
      enc += cipher.final('base64');
      return [enc, cipher.getAuthTag()];
    };
  
    // decrypt decodes base64-encoded ciphertext into a utf8-encoded string
    const decrypt = (enc, iv, authTag) => {
      const decipher = crypto.createDecipheriv(ALGO, key, iv);
      decipher.setAuthTag(authTag);
      let str = decipher.update(enc, 'base64', 'utf8');
      str += decipher.final('utf8');
      return str;
    };
  
    return {
      encrypt,
      decrypt,
    };
  };

//普通加密解密测试
function testCommon(){
    const data = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";       //待加密数据
    const key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y=";
    const iv64 = 'j2tauE9NI5aBvxso';        
    const iv = Buffer.from(iv64, 'base64');     //固定向量
    //const iv = Buffer.from(crypto.randomBytes(16), 'utf8');     //随机向量
    //console.log('iv:' + iv);

    const aesCipher = aes256gcm(Buffer.from(key,'base64'));
    const [encrypted, authTag] = aesCipher.encrypt(data,iv);
    
    console.log('encrypted: ' + encrypted);
    console.log('authTag64:   ' + Buffer.from(authTag).toString('base64'));
    
    const decrypted = aesCipher.decrypt(encrypted, iv, authTag);
    console.log('decrypted: ' + decrypted);
}

//解密服务器发来的数据
function testDecryptFromServer(){
    const key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y=";
    const cipherTextServer = "S89syga21yniBAlANVllVqYplznwF1YOkk04d4rHBQGata6bDysOsGCGUEgUJ0hdEyVkFBNANXrplMry29B+F9ChfJjDVGUBiMb83qlsKQ+560V4+51TzFxi3kf7IuLfi6Va0H7h5I0=";       //Base64的加密后数据。服务端返回
    const iv64 = 'j2tauE9NI5aBvxso';        //base64的初始向量，服务端返回       
    const iv = Buffer.from(iv64, 'base64');
    //服务端的实现里，密文和tag是放在一起的，所以客户端收到后首先要分开密文和tag，tag约定为16个字节长度。
    var cipherBuffer = Buffer.from(cipherTextServer, 'base64');
    var encrypted = cipherBuffer.slice(0, cipherBuffer.byteLength - 16);
    var authTag = cipherBuffer.slice(cipherBuffer.byteLength - 16, cipherBuffer.byteLength);

    const aesCipher = aes256gcm(Buffer.from(key,'base64'));
    const decrypted = aesCipher.decrypt(Buffer.from(encrypted).toString('base64'), iv, authTag);
    console.log('decrypted: ' + decrypted);
}

///生成发送给服务器的数据
function testEncryptToServer(){
    const data = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";       //待加密数据
    const key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y=";
    const iv64 = 'j2tauE9NI5aBvxso';        
    //const iv = Buffer.from(iv64, 'base64');     //固定向量，测试用
    const iv = Buffer.from(crypto.randomBytes(16), 'utf8');     //随机向量,要发给服务器
    console.log('iv64:' + Buffer.from(iv).toString('base64'));

    const aesCipher = aes256gcm(Buffer.from(key,'base64'));
    const [encrypted, authTag] = aesCipher.encrypt(data,iv);
    console.log('encrypted: ' + encrypted);
    console.log('authTag64:   ' + Buffer.from(authTag).toString('base64'));
    //拼装 encrypted + authTag64
    const bufFin = Buffer.concat([Buffer.from(encrypted,'base64'), authTag]);       //拼装后进行base64编码才是发送给服务器的数据
    console.log('cipherTextServer:  ' + Buffer.from(bufFin).toString('base64'));
}

console.log("Hello demo-nodejs");

//testCommon();
//testDecryptFromServer();
testEncryptToServer();

