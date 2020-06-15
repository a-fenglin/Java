import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.AlgorithmParameters;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.BrokenJCEBlockCipher.BrokePBEWithMD5AndDES;
import org.bouncycastle.util.encoders.Hex;

public class TestECIES {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		//KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECIES");  // ����ĳ�EC
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
		KeyPair keyPair = kpg.generateKeyPair();
		PublicKey publicKey = keyPair.getPublic();
		PrivateKey privateKey = keyPair.getPrivate();
		
		byte[] plaintText = "hello world".getBytes();
		byte[] cipherText = null;
		
		// ����
		//Cipher cipher = Cipher.getInstance("ECIESWITHAES-CBC");  // ����ĳ�SM2
		Cipher cipher = Cipher.getInstance("SM2");
		cipher.init(Cipher.ENCRYPT_MODE, publicKey);
		cipherText = cipher.doFinal(plaintText);
		System.out.println("����:" + Hex.toHexString(cipherText));
		AlgorithmParameters parameters = cipher.getParameters();
		
		String plainFileName = "F:\\Colleadge\\����ѧ����\\ʵ����\\ʵ��5.doc";
		String cipherFileName = "F:\\Colleadge\\����ѧ����\\ʵ����\\ʵ��5.enc";
		String decryptedFileName = "F:\\Colleadge\\����ѧ����\\ʵ����\\ʵ��5.txt";
		try (FileInputStream fis = new FileInputStream(plainFileName);
				CipherInputStream cis = new CipherInputStream(fis, cipher);
				FileOutputStream fos = new  FileOutputStream(cipherFileName)){
			byte[] buffer = new byte[512];
			int n = -1;
			while ((n = cis.read(buffer)) != -1) {
				fos.write(buffer, 0, n);
				
			}
		}
		
		cipher.init(Cipher.DECRYPT_MODE, privateKey, cipher.getParameters());
		try (FileInputStream fis = new FileInputStream(cipherFileName);
				CipherInputStream cis = new CipherInputStream(fis, cipher);
				FileOutputStream fos = new  FileOutputStream(decryptedFileName)){
			byte[] buffer = new byte[512];
			int n = -1;
			while ((n = cis.read(buffer)) != -1) {
				fos.write(buffer, 0, n);
				
			}
		}
		
		
		// ����
		cipher.init(Cipher.DECRYPT_MODE, privateKey, parameters);
		plaintText = cipher.doFinal(cipherText);
		System.out.println("���ܺ�����ģ�" + new String(plaintText));
	}
}
