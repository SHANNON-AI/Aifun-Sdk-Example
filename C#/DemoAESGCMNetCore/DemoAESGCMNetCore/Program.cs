using System;
using System.Security.Cryptography;
using System.Text;

namespace DemoAESGCMNetCore
{
    /// <summary>
    /// AES 256 GCM 加密解密算法，在.net core 3.0和更高版本的实现，这个版本的.net已经存在系统api可以直接使用
    /// 算法是对称加密算法，秘钥是256位，每次加密需要生成一个12位字节的随机向量iv，随机向量参与加密计算
    /// 加密后得到和原始数据同样字节长度的密文ciphertext和16位的数据验证码tag，
    /// ciphertext 和 tag 以字节的方式拼接，然后进行Base64编码得到最终密文，随机向量iv也进行Base64编码，一起发给接收端
    /// </summary>
    class Program
    {
        static readonly int AES_KEY_SIZE = 256;         //秘钥的长度
        static readonly int GCM_IV_LENGTH = 12;         //初始向量的长度
        static readonly int GCM_TAG_LENGTH = 16;        //消息验证码tag的长度

        static void encrypt(byte[] plaintext, byte[] key, byte[] iv, byte[] ciphertext,byte[] tag)
        {
            var aesGcm = new AesGcm(key);
            aesGcm.Encrypt(iv, plaintext, ciphertext, tag, null);
            Console.WriteLine("ciphertext:  " + Convert.ToBase64String(ciphertext));
            Console.WriteLine("tag: " + Convert.ToBase64String(tag));
        }

        /*
        * 解密算法
        */
        static void decrypt(byte[] ciphertext, byte[] tag,byte[] key, byte[] iv, byte[] plaintext)
        {
            var aesGcm = new AesGcm(key);
            aesGcm.Decrypt(iv, ciphertext, tag, plaintext,null);
            Console.WriteLine("plaintext:   " + Encoding.UTF8.GetString(plaintext));
        }

        /// <summary>
        /// 固定向量的加密测试
        /// </summary>
        static void testFixIV()
        {
            string data = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";		//待加密数据
        	string key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; //秘钥(Base64格式)
            String iv64 = "j2tauE9NI5aBvxso";
            byte[] iv = Convert.FromBase64String(iv64);
            byte[] ciphertext = new byte[Encoding.UTF8.GetBytes(data).Length];
            byte[] tag = new byte[GCM_TAG_LENGTH];
            encrypt(Encoding.UTF8.GetBytes(data), Convert.FromBase64String(key), iv, ciphertext,tag);
            byte[] plaintext = new byte[ciphertext.Length];
            decrypt(ciphertext,tag, Convert.FromBase64String(key), iv, plaintext);
            
        }

        /// <summary>
        /// 随机向量的加密测试
        /// </summary>
        static void testRandomIV()
        {
            string data = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";       //待加密数据
            string key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; //秘钥(Base64格式)
            byte[] iv = new byte[GCM_IV_LENGTH];
            Random random = new Random();
            random.NextBytes(iv);
            Console.WriteLine("iv64:   " + Convert.ToBase64String(iv));
            byte[] ciphertext = new byte[Encoding.UTF8.GetBytes(data).Length];
            byte[] tag = new byte[GCM_TAG_LENGTH];
            encrypt(Encoding.UTF8.GetBytes(data), Convert.FromBase64String(key), iv, ciphertext, tag);
            byte[] plaintext = new byte[ciphertext.Length];
            decrypt(ciphertext, tag, Convert.FromBase64String(key), iv, plaintext);
            
        }

        /// <summary>
        /// 解密服务器发来的数据
        /// </summary>
        static void testDecryptFromServer()
        {
            string key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; //秘钥(Base64格式),cp方持有	
            
            string cipherTextServer = "S89syga21yniBAlANVllVqYplznwF1YOkk04d4rHBQGata6bDysOsGCGUEgUJ0hdEyVkFBNANXrplMry29B+F9ChfJjDVGUBiMb83qlsKQ+560V4+51TzFxi3kf7IuLfi6Va0H7h5I0=";		//Base64的加密后数据。服务端返回
	        string iv64 = "j2tauE9NI5aBvxso";		//base64的初始向量，服务端返回
            //服务端的实现里，密文和tag是放在一起的，所以客户端收到后首先要分开密文和tag，tag约定为16个字节长度。
            byte[] cipherByteServer = Convert.FromBase64String(cipherTextServer);
            byte[] cipherByte = new byte[Convert.FromBase64String(cipherTextServer).Length - 16];       //密文
            byte[] tagByte = new byte[16];          //tag
            Array.Copy(cipherByteServer, cipherByte, cipherByteServer.Length-16);
            Console.WriteLine("cipher64:    " + Convert.ToBase64String(cipherByte));
            
            Array.Copy(cipherByteServer, cipherByteServer.Length - 16, tagByte, 0,16);
            Console.WriteLine("tag64:    " + Convert.ToBase64String(tagByte));

            byte[] plaintext = new byte[cipherByte.Length];
            decrypt(cipherByte, tagByte, Convert.FromBase64String(key), Convert.FromBase64String(iv64), plaintext);
        }

        /// <summary>
        /// 生成发送给服务器的数据
        /// </summary>
        static void testEncryptToServer()
        {
            string key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; //秘钥(Base64格式),cp方持有	

            string plaintext = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";
            byte[] iv = new byte[GCM_IV_LENGTH];
            Random random = new Random();
            random.NextBytes(iv);       //随机生成iv
            string iv64 = "j2tauE9NI5aBvxso";
            //string iv64 = Convert.ToBase64String(iv);     //最终发给服务器的随机向量
            Console.WriteLine("iv64:   " + iv64);
            byte[] cipherByte = new byte[Encoding.UTF8.GetBytes(plaintext).Length];
            byte[] tagByte = new byte[GCM_TAG_LENGTH];
            encrypt(Encoding.UTF8.GetBytes(plaintext), Convert.FromBase64String(key), Convert.FromBase64String(iv64), cipherByte, tagByte);
            //拼装cipherByte + tagByte
            byte[] cipherByteServer = new byte[cipherByte.Length + tagByte.Length];
            Array.Copy(cipherByte, cipherByteServer, cipherByte.Length);
            Array.Copy(tagByte, 0, cipherByteServer, cipherByteServer.Length- GCM_TAG_LENGTH, GCM_TAG_LENGTH);
            string cipherText = Convert.ToBase64String(cipherByteServer);       //最终发给服务器的加密字符串
            Console.WriteLine("cipherText:    " + cipherText);

        }

        static void Main(string[] args)
        {
            Console.WriteLine("Hello DemoAESGCMNetCore!");
            //testFixIV();
            //testRandomIV();
            //testDecryptFromServer();
            testEncryptToServer();
        }
    }
}
