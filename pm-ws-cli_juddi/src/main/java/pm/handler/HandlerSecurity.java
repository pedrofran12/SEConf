package pm.handler;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.KeyGenerator;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

public class HandlerSecurity {

	private static final String serverKeyPath = "./ServerPublic.key";
	private static final String alias = "client";
	private static final char[] password = "benfica".toCharArray();
	private static final String MAC_SIGNATURE = "SHA256withRSA";

	private PrivateKey _privateKeyClient;
	private PublicKey _publicKeyServer;

	public HandlerSecurity() throws IOException, NoSuchAlgorithmException {
		try {
			// Key do servidor
			System.out.println("Reading key from file " + serverKeyPath + " ...");
			byte[] keyBytes = Files.readAllBytes(new File(serverKeyPath).toPath());
			X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			_publicKeyServer = kf.generatePublic(spec);
			System.out.println("\n"+_publicKeyServer.toString() + "\n");

			KeyStore ks = KeyStore.getInstance("JKS");
			InputStream readStream = new FileInputStream("src/main/resources/KeyStore.jks");
			ks.load(readStream, password);
			_privateKeyClient = (PrivateKey) ks.getKey(alias, password);
			readStream.close();

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	public PublicKey getPublicKey() {
		return _publicKeyServer;
	}

	private PrivateKey getPrivateKey() {
		return _privateKeyClient;
	}

	/** auxiliary method to make the MAC */
	public byte[] makeSignature(byte[] bytes) throws Exception {
		PrivateKey privateKey = getPrivateKey();

		Signature cipher = Signature.getInstance(MAC_SIGNATURE);
		cipher.initSign(privateKey);
		cipher.update(bytes);

		return cipher.sign();
	}

	/**
	 * auxiliary method to calculate new digest from text and compare it to the
	 * to deciphered digest
	 */
	public boolean verifySignature(byte[] cipherDigest, byte[] bytes) throws Exception {
		PublicKey k = getPublicKey();

		Signature cipher = Signature.getInstance(MAC_SIGNATURE);
		cipher.initVerify(k);
		cipher.update(bytes);

		return cipher.verify(cipherDigest);
	}

	public Key generateKey() throws GeneralSecurityException, IOException {
		// get an AES private key
		System.out.println("Generating AES key ...");
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		Key key = keyGen.generateKey();

		System.out.println("Finish generating AES key");
		byte[] encoded = key.getEncoded();
		System.out.println("Key:");
		System.out.println(printHexBinary(encoded));

		return key;
	}
}
