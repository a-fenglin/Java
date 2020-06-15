import java.io.FileInputStream;

import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Collections;
import java.util.Enumeration;

public class Test {
	public static void main(String[] args) throws Exception {
		KeyStore keyStore = KeyStore.getInstance("PKCS12");
		try (FileInputStream fis = new FileInputStream("F:\\java-2019-03\\javaprject\\Less4\\work")) {
			// ����KeyStore���󣬲�����Կ���ļ��ж�������
			char[] password = "123456".toCharArray();
			keyStore.load(fis, password);
			// ��������ӡ��Կ���е����б���
			Enumeration<String> aliases = keyStore.aliases();
			System.out.println("��Կ���ļ��е���Կ��Ŀ�������£�");
			Collections.list(aliases).forEach(System.out::println);

			// ��ȡ��Կ��myrsakey�е�˽Կ������һ��˽Կ���󣬲���ӡ������
			KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(
					password);
			KeyStore.PrivateKeyEntry keyEntry = (PrivateKeyEntry) keyStore
					.getEntry("myeckey", protParam);
			ECPrivateKey privateKey = (ECPrivateKey) keyEntry.getPrivateKey();
			System.out.println("˽Կ: " + ( (RSAPrivateKey) privateKey).getPrivateExponent());

			// ��ȡ��Կ��myrsakey�еĹ�Կ��Ӧ����ǩ��֤�飬��ӡ֤�����ݺ͹�Կֵ
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate("myeckey");
			System.out.println("֤�������Ϣ" + certificate);
			ECPublicKey publicKey = (ECPublicKey) certificate.getPublicKey();
			System.out.println("��Կ��" + publicKey);
		}
	}
}

