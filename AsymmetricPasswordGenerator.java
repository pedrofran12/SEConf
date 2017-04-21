import java.io.File;
import java.io.FileOutputStream;
import java.nio.file.Files;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

public class AsymmetricPasswordGenerator {
	public static void main(String[] args) throws Exception{
		if(args.length < 1)
			throw new Exception("first argument: number of keys");
		int n = Integer.parseInt(args[0]);
		for(int i = 8080; i<8080 + n; i++) {
		    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
	        keyGen.initialize(2048);
	        KeyPair keys = keyGen.generateKeyPair();
		    
	        System.out.println("Private Key:");
	        PrivateKey privKey = keys.getPrivate();
	        byte[] privKeyEncoded = privKey.getEncoded();
	        System.out.println(printHexBinary(privKeyEncoded));
	        System.out.println("Public Key:");
	        PublicKey pubKey = keys.getPublic();
	        byte[] pubKeyEncoded = pubKey.getEncoded();
	        System.out.println(printHexBinary(pubKeyEncoded));  
	        
	        
	        FileOutputStream fos = new FileOutputStream("ServerPrivate" + i + ".key");
	        fos.write(privKeyEncoded);
		fos.close();
		    
		FileOutputStream fos2 = new FileOutputStream("ServerPublic" + i + ".key");
		fos2.write(pubKeyEncoded);
		fos2.close();
		    
/*		    
		    byte[] keyBytes2 = Files.readAllBytes(new File("Keys.key").toPath());
	
		    X509EncodedKeySpec spec2 =
		      new X509EncodedKeySpec(keyBytes2);
		    KeyFactory kf2 = KeyFactory.getInstance("RSA");
		    Key _serverPublicKey = kf2.generatePublic(spec2);
			byte[] pkeyEnc = _serverPublicKey.getEncoded();
		    
		    System.out.println("\n\n\n\n\n PKEY\n\n\n"+printHexBinary(pkeyEnc));*/
		}
	}
}
