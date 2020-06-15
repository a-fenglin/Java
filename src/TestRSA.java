import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;
import javax.naming.InitialContext;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

public class TestRSA {
	public static void main(String[] args) throws Exception {
		
		// RSA字符串加密
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		
//		Security.addProvider(new BouncyCastleProvider());
//		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Elgamal");
		// 椭圆曲线就写EC
		
		kpg.initialize(1024);  // 椭圆曲线直接把这个注释
		KeyPair keyPair = kpg.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		byte[] plaintText = "hello world".getBytes();
		byte[] cipherText = null;
		
		// 加密
		//Cipher cipher = Cipher.getInstance("Elgamal/ECB/PKCS1Padding");
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		cipherText = cipher.doFinal(plaintText);
		System.out.println("密文:" + Hex.toHexString(cipherText));
		
		// 解密
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		plaintText = cipher.doFinal(cipherText);
		System.out.println("解密后的明文：" + new String(plaintText));
	}
}
