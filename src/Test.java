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
			// 创建KeyStore对象，并从密钥库文件中读入内容
			char[] password = "123456".toCharArray();
			keyStore.load(fis, password);
			// 遍历并打印密钥库中的所有别名
			Enumeration<String> aliases = keyStore.aliases();
			System.out.println("密钥库文件中的密钥条目别名如下：");
			Collections.list(aliases).forEach(System.out::println);

			// 读取密钥对myrsakey中的私钥，创建一个私钥对象，并打印其内容
			KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(
					password);
			KeyStore.PrivateKeyEntry keyEntry = (PrivateKeyEntry) keyStore
					.getEntry("myeckey", protParam);
			ECPrivateKey privateKey = (ECPrivateKey) keyEntry.getPrivateKey();
			System.out.println("私钥: " + ( (RSAPrivateKey) privateKey).getPrivateExponent());

			// 读取密钥对myrsakey中的公钥对应的自签名证书，打印证书内容和公钥值
			X509Certificate certificate = (X509Certificate) keyStore.getCertificate("myeckey");
			System.out.println("证书基本信息" + certificate);
			ECPublicKey publicKey = (ECPublicKey) certificate.getPublicKey();
			System.out.println("公钥：" + publicKey);
		}
	}
}

