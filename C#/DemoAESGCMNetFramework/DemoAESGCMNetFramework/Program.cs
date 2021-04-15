using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace DemoAESGCMNetFramework
{
    /// <summary>
    /// AES 256 GCM 加密解密算法，在.net core 3.0之前的版本，需要使用第三方库BouncyCastle
    /// 算法是对称加密算法，秘钥是256位，每次加密需要生成一个12位字节的随机向量iv，随机向量参与加密计算
    /// 加密后得到和原始数据同样字节长度的密文ciphertext和16位的数据验证码tag，两者拼接后得到最终密文
    /// 最终密文进行Base64编码得到最终密文，随机向量iv也进行Base64编码，一起发给接收端
    /// </summary>
    class Program
    {
        static readonly int AES_KEY_SIZE = 256;         //秘钥的长度
        static readonly int GCM_IV_LENGTH = 12;         //初始向量的长度
        static readonly int GCM_TAG_LENGTH = 16;        //消息验证码tag的长度

        static byte[] encrypt(byte[] plaintext, byte[] key, byte[] iv)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), GCM_TAG_LENGTH * 8, iv, null);
            cipher.Init(true, parameters);
            var cipherText = new byte[cipher.GetOutputSize(plaintext.Length)];
            var len = cipher.ProcessBytes(plaintext, 0, plaintext.Length, cipherText, 0);
            cipher.DoFinal(cipherText, len);
            Console.WriteLine("ciphertext:  " + Convert.ToBase64String(cipherText));

            byte[] cipherByte = new byte[cipherText.Length - 16];       //密文
            byte[] tagByte = new byte[16];          //tag
            Array.Copy(cipherText, cipherByte, cipherText.Length - 16);
            Console.WriteLine("cipher64:    " + Convert.ToBase64String(cipherByte));

            Array.Copy(cipherText, cipherText.Length - 16, tagByte, 0, 16);
            Console.WriteLine("tag64:    " + Convert.ToBase64String(tagByte));
            return cipherText;
        }

        /*
        * 解密算法
        */
        static byte[] decrypt(byte[] cipherText, byte[] key, byte[] iv)
        {
            var cipher = new GcmBlockCipher(new AesEngine());
            var parameters = new AeadParameters(new KeyParameter(key), GCM_TAG_LENGTH * 8, iv, null);
            cipher.Init(false, parameters);
            //var cipherText = cipherReader.ReadBytes(message.Length - nonSecretPayloadLength - nonce.Length);
            var plainText = new byte[cipher.GetOutputSize(cipherText.Length)];
            try
            {
                var len = cipher.ProcessBytes(cipherText, 0, cipherText.Length, plainText, 0);
                cipher.DoFinal(plainText, len);
            }
            catch (InvalidCipherTextException ex)
            {
                Console.WriteLine("InvalidCipherTextException:" + ex.Message);
            }
            Console.WriteLine("plaintext:   " + Encoding.UTF8.GetString(plainText));
            return plainText;
        }

        /// <summary>
        /// 固定向量的加密测试
        /// </summary>
        static void testFixIV()
        {
            string data = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";       //待加密数据
            string key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; //秘钥(Base64格式)
            String iv64 = "j2tauE9NI5aBvxso";
            byte[] iv = Convert.FromBase64String(iv64);
            
            byte[] ciphertext = encrypt(Encoding.UTF8.GetBytes(data), Convert.FromBase64String(key), iv);
          
            byte[] plaintext = decrypt(ciphertext, Convert.FromBase64String(key), iv);

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
            
            byte[] ciphertext = encrypt(Encoding.UTF8.GetBytes(data), Convert.FromBase64String(key), iv);
            
            byte[] plaintext = decrypt(ciphertext, Convert.FromBase64String(key), iv);

        }

        /// <summary>
        /// 解密服务器发来的数据
        /// </summary>
        static void testDecryptFromServer()
        {
            string key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; //秘钥(Base64格式),cp方持有	

            string cipherTextServer = "S89syga21yniBAlANVllVqYplznwF1YOkk04d4rHBQGata6bDysOsGCGUEgUJ0hdEyVkFBNANXrplMry29B+F9ChfJjDVGUBiMb83qlsKQ+560V4+51TzFxi3kf7IuLfi6Va0H7h5I0=";       //Base64的加密后数据。服务端返回
            string iv64 = "j2tauE9NI5aBvxso";		//base64的初始向量，服务端返回
            
            byte[] cipherByteServer = Convert.FromBase64String(cipherTextServer);
           
            byte[] plaintext = decrypt(cipherByteServer, Convert.FromBase64String(key), Convert.FromBase64String(iv64));
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
            //string iv64 = "j2tauE9NI5aBvxso";
            string iv64 = Convert.ToBase64String(iv);     //最终发给服务器的随机向量
            Console.WriteLine("iv64:   " + iv64);
            byte[] cipherByte = new byte[Encoding.UTF8.GetBytes(plaintext).Length];
            byte[] tagByte = new byte[GCM_TAG_LENGTH];
            byte[] cipherByteServer = encrypt(Encoding.UTF8.GetBytes(plaintext), Convert.FromBase64String(key), Convert.FromBase64String(iv64));
            

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
