<?php
//用户请使用UTF-8作为php源码文件的保存格式，避免出现乱码问题
//加密和解密的算法基于AEAD AES 256 GCM，请打开php的openssl扩展支持
//该实现需要版本PHP5.4以上版本
//该实现依赖第三方库 https://github.com/Spomky-Labs/php-aes-gcm

require './vendor/autoload.php';


use AESGCM\AESGCM;

function GetRandStr($length){
 //字符组合
 $str = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
 $len = strlen($str)-1;
 $randstr = '';
 for ($i=0;$i<$length;$i++) {
  $num=mt_rand(0,$len);
  $randstr .= $str[$num];
 }
 return $randstr;
}


/*
* 加密算法
*/
function encrypt($data,$key,$iv,&$tag){	
	list($ciphertext, $tag) = AESGCM::encrypt($key, $iv, $data, NULL);
	echo "ciphertext64:	" . base64_encode($ciphertext) . "\r\n";
	return $ciphertext;
}

/*
* 解密算法
*/
function decrypt($ciphertext,$key,$iv,$tag){
	$data = AESGCM::decrypt($key, $iv, $ciphertext, NULL, $tag);
	echo "decrypt:	" . $data . "\r\n";
	return $data;
}


/*
* 加密解密验证-固定初始向量
* 
*/
function test1(){
	$data = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";		//待加密数据

	$key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; //秘钥(Base64格式)
	//$algo = 'aes-256-gcm';
	$iv64 = "j2tauE9NI5aBvxso";
	echo "iv64:	" . $iv64 . "\r\n";
	$tag = NULL;
	$ciphertext = encrypt($data,base64_decode($key),base64_decode($iv64),$tag);
	echo "tag64:	" . base64_encode($tag) . "\r\n";
	decrypt($ciphertext,base64_decode($key),base64_decode($iv64),$tag);
}

/*
* 加密解密验证-随机初始化向量
*/
function test2(){
	$data = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";		//待加密数据
	$key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; //秘钥(Base64格式)
	$algo = 'aes-256-gcm';
	$iv = GetRandStr(openssl_cipher_iv_length($algo));	//随机向量
	echo "iv64:	" .base64_encode($iv) . "\r\n";
	$tag = NULL;
	$ciphertext = encrypt($data,base64_decode($key),$iv,$tag);
	echo "tag64:	" . base64_encode($tag) . "\r\n";
	decrypt($ciphertext,base64_decode($key),$iv,$tag);

}


/*
* 服务器数据解密范例
*/
function test3(){
	$key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; //秘钥(Base64格式),cp方持有
	
	$cipherText = "S89syga21yniBAlANVllVqYplznwF1YOkk04d4rHBQGata6bDysOsGCGUEgUJ0hdEyVkFBNANXrplMry29B+F9ChfJjDVGUBiMb83qlsKQ+560V4+51TzFxi3kf7IuLfi6Va0H7h5I0=";		//Base64的加密后数据。服务端返回
	$iv64 = "j2tauE9NI5aBvxso";		//base64的初始向量，服务端返回
	//服务端的实现里，密文和tag是放在一起的，所以客户端收到后首先要分开密文和tag，tag约定为16个字节长度。
	//echo base64_decode($cipherText);
	$array = unpack("C*", base64_decode($cipherText));
	//print_r($array);
	$arrayCipher = array_slice($array, 0, count($array)-16);		//获得原始密文
	$arrayTag = array_slice($array, count($array)-16);			//获得tag
	$string = "";
	foreach ($arrayCipher as $chr) {
		$string .= chr($chr);
	}
	$cipher64 = base64_encode($string);
	echo "cipher64:	" . $cipher64 . "\r\n";
	
	$string = "";
	foreach ($arrayTag as $chr) {
		$string .= chr($chr);
	}
	$tag64 = base64_encode($string);
	echo "tag64:	" . $tag64 . "\r\n";

	decrypt(base64_decode($cipher64), base64_decode($key), base64_decode($iv64), base64_decode($tag64));
	
	
}

/*
* 客户端数据加密后发往服务器
*/
function test4(){
	$key = "mlMUtKNZL/B1clOS8BFkO7mDuRZPJAMlVmo+vtNzo9Y="; //秘钥(Base64格式),cp方持有
	$data = "This is a plain text which need to be encrypted by Java AES 256 GCM Encryption Algorithm";		//待加密数据
	$iv64 = "j2tauE9NI5aBvxso";		//base64的初始向量，由客户端使用 random_bytes 函数生成后进行base64编码，需要发往服务器
	$tag = NULL;
	$cipher = encrypt($data,base64_decode($key),base64_decode($iv64),$tag);
	$tag64 = base64_encode($tag);
	echo "cipher64:	" . base64_encode($cipher) . "\r\n";
	echo "tag64:	" . $tag64 . "\r\n";
	//需要把$cipher 和 $tag 这两个二进制数据，拼接成新的二进制数据，再进行Base64编码得到最终加密数据
	$arrayCipher = unpack("C*", $cipher);
	$arrayTag = unpack("C*", $tag);
	$array = array_merge($arrayCipher,$arrayTag);
	
	$string = "";
	foreach ($array as $chr) {
		$string .= chr($chr);
	}
	$cipherText = base64_encode($string);		//最终加密数据，需要发往服务器
	echo "cipherText:	" . $cipherText . "\r\n";
	
}

echo "Hello world\r\n";

//test1();
//test2();
test3();
//test4();





