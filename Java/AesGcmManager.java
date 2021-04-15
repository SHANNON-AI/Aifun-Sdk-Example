package com.aifun.admin.manager;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * AEAD_AES_256_GCM 加密解密工具类
 */
@Component
public class AesGcmManager {

    private static final Logger logger = LoggerFactory.getLogger(AesGcmManager.class);

    static String plainText = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";
    public static final int AES_KEY_SIZE = 256;
    public static final int GCM_IV_LENGTH = 12;
    public static final int GCM_TAG_LENGTH = 16;


    /**
     * 加密
     *
     * @param plaintext 原始内容转换的字节数组
     * @param key       秘钥
     * @param IV        加密使用的随机串初始化向量，注意，向量必须传递给目标，否则无法解密
     */
    public byte[] encrypt(byte[] plaintext, SecretKey key, byte[] IV) throws Exception {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);

        // Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, gcmParameterSpec);

        // Perform Encryption
        byte[] cipherText = cipher.doFinal(plaintext);

        return cipherText;
    }

    /**
     * 解密
     *
     * @param cipherText 密文
     * @param key        秘钥
     * @param IV         加密使用的随机串初始化向量，注意，向量必须传递给目标，否则无法解密
     */
    public String decrypt(byte[] cipherText, SecretKey key, byte[] IV) throws Exception {
        // Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");

        // Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), "AES");

        // Create GCMParameterSpec
        GCMParameterSpec gcmParameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, IV);

        // Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, gcmParameterSpec);

        // Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);

        return new String(decryptedText);
    }

    /**
     * 生成key
     */
    public String generateKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEY_SIZE);

        SecretKey key = keyGenerator.generateKey();     //生成秘钥
        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());   //key转成base64字符串
        return encodedKey;
    }

    public static void main(String[] args) throws Exception {
        AesGcmManager aesGcmManager = new AesGcmManager();
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(AES_KEY_SIZE);

        // Generate Key
        SecretKey key = keyGenerator.generateKey();     //生成秘钥

        String encodedKey = Base64.getEncoder().encodeToString(key.getEncoded());   //key转成base64字符串
        System.out.println("key base64 text : " + encodedKey);
        // decode the base64 encoded string
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);     //字符串转回原来的key
        // rebuild key using SecretKeySpec
        SecretKey originalKey = new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");

        byte[] IV = new byte[GCM_IV_LENGTH];        //随机数
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);

        System.out.println("Original Text : " + plainText);

        byte[] cipherText = aesGcmManager.encrypt(plainText.getBytes(), key, IV);
        System.out.println("Encrypted Text : " + Base64.getEncoder().encodeToString(cipherText));

        String decryptedText = aesGcmManager.decrypt(cipherText, key, IV);
        System.out.println("DeCrypted Text : " + decryptedText);
    }

}
