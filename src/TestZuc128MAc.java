import java.security.NoSuchAlgorithmException;
import java.security.Security;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jcajce.provider.symmetric.Zuc.Zuc128;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import org.bouncycastle.crypto.macs;
import org.bouncycastle.crypto.macs.Zuc128Mac;

public class TestZuc128MAc {
	public static void main(String[] args) throws Exception {
		Security.addProvider(new BouncyCastleProvider());
		String s = "123456";
		//Mac md = null ;
		//String aString = md.getAlgorithm();
		//Zuc128Mac mac = Zuc128Mac.getInstance("EC");
		Zuc128Mac md = new Zuc128Mac();
		md.getAlgorithmName();
		
		// ��ʼ��HmacMD5ժҪ�㷨����Կ������
				KeyGenerator generator = KeyGenerator.getInstance("HmacMD5");
				// ������Կ
				SecretKey secretKey = generator.generateKey();
				// �����Կ
				byte[] key = secretKey.getEncoded();
				
				// ��ԭ��Կ
				SecretKey secretKey2 = new SecretKeySpec(key, "HmacMD5");
		
		//md.init();
		Mac mac = Mac.getInstance("ZUC-128");
		
	}

	
}
