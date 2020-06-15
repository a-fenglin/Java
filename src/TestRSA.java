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
		
		// RSA�ַ�������
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
		
//		Security.addProvider(new BouncyCastleProvider());
//		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Elgamal");
		// ��Բ���߾�дEC
		
		kpg.initialize(1024);  // ��Բ����ֱ�Ӱ����ע��
		KeyPair keyPair = kpg.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		byte[] plaintText = "hello world".getBytes();
		byte[] cipherText = null;
		
		// ����
		//Cipher cipher = Cipher.getInstance("Elgamal/ECB/PKCS1Padding");
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		cipherText = cipher.doFinal(plaintText);
		System.out.println("����:" + Hex.toHexString(cipherText));
		
		// ����
		cipher.init(Cipher.DECRYPT_MODE, privateKey);
		plaintText = cipher.doFinal(cipherText);
		System.out.println("���ܺ�����ģ�" + new String(plaintText));
	}
}
