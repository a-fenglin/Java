import java.security.Provider.Service;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ListSigs {
	public static void main(String[] args) {
		//Á÷Ê½Ð´·¨
//		new BouncyCastleProvider().getServices().stream()
//				.filter(s -> "Signature".equals(s.getType()))
//				.map(Service::getAlgorithm)
//				.sorted()
//				.forEach(System.out::println);
		
		for (Service service : new BouncyCastleProvider().getServices()) {
			if (service.getType().equals("MessageDigest")) {  // Signature
				System.out.println(service.getAlgorithm());
			}
		}
	}
}
