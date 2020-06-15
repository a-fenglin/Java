import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.crypto.macs.Zuc128Mac;


public class TestMac {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		String s = "123456";
		
		// ��ʼ��HmacMD5ժҪ�㷨����Կ������
		//KeyGenerator generator = KeyGenerator.getInstance("ZUC-128");
		//KeyGenerator generator = KeyGenerator.getInstance("ZUC-256");
		KeyGenerator generator = KeyGenerator.getInstance("ZUC-256");
		// ������Կ
		SecretKey secretKey = generator.generateKey();
		// �����Կ
		
		byte[] key = secretKey.getEncoded();
		
		byte[] ivValue = new byte[25];
		SecureRandom random = new SecureRandom();
		random.nextBytes(ivValue);
		IvParameterSpec iv = new IvParameterSpec(ivValue);
		
		// ��ԭ��Կ
		//SecretKey secretKey2 = new SecretKeySpec(key, "ZUC-128");
		//SecretKey secretKey2 = new SecretKeySpec(key, "ZUC-256");
		SecretKey secretKey2 = new SecretKeySpec(key, "ZUC-256");
		// ʵ����Mac
		Mac mac = Mac.getInstance("ZUC-256-64");
		//Mac mac = Mac.getInstance(secretKey2.getAlgorithm());
		// ��ʼ��mac
		mac.init(secretKey2,iv);
		// ִ����ϢժҪ
		byte[] digest = mac.doFinal(s.getBytes());
		
		for(byte b : digest) {
			System.out.printf("%02x", b);
		}
		
		
	}


}
