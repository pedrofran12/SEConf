package pm.handler;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import utilities.ObjectUtil;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

public class HandlerSecurity {

	private static final String publicKeyPath = "./ServerPublic.key";
	private static final String privateKeyPath = "./ServerPrivate.key";
	private static final String MAC_SIGNATURE = "SHA256withRSA";

	private PrivateKey _privateKey;
	private PublicKey _publicKey;

	public HandlerSecurity() throws IOException, NoSuchAlgorithmException {
		try {
			KeyFactory kf = KeyFactory.getInstance("RSA");

			// READ PUBLIC KEY
			System.out.println("Reading key from file " + publicKeyPath + " ...");
			byte[] keyBytesPublic = Files.readAllBytes(new File(publicKeyPath).toPath());
			X509EncodedKeySpec specPublic = new X509EncodedKeySpec(keyBytesPublic);
			_publicKey = kf.generatePublic(specPublic);

			// READ PRIVATE KEY
			System.out.println("Reading key from file " + privateKeyPath + " ...");
			byte[] keyBytesPrivate = Files.readAllBytes(new File(privateKeyPath).toPath());
			PKCS8EncodedKeySpec specPrivate = new PKCS8EncodedKeySpec(keyBytesPrivate);
			_privateKey = kf.generatePrivate(specPrivate);

		} catch (Exception e) {
			System.out.println("Generating RSA key ...");
			KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
			keyGen.initialize(1024);
			KeyPair keys = keyGen.generateKeyPair();
			System.out.println("Finish generating RSA keys");

			System.out.println("Private Key:");
			_privateKey = keys.getPrivate();
			byte[] privKeyEncoded = _privateKey.getEncoded();
			System.out.println(printHexBinary(privKeyEncoded));
			System.out.println("Public Key:");
			_publicKey = keys.getPublic();
			byte[] pubKeyEncoded = _publicKey.getEncoded();
			System.out.println(printHexBinary(pubKeyEncoded));

			// SAVE GENERATED PASSWORDS
			System.out.println("Writing Private key to '" + privateKeyPath + "' ...");
			FileOutputStream privFos = new FileOutputStream(privateKeyPath);
			privFos.write(privKeyEncoded);
			privFos.close();
			System.out.println("Writing Public key to '" + publicKeyPath + "' ...");
			FileOutputStream pubFos = new FileOutputStream(publicKeyPath);
			pubFos.write(pubKeyEncoded);
			pubFos.close();
		}
	}

	public PublicKey getPublicKey() {
		return _publicKey;
	}

	private PrivateKey getPrivateKey() {
		return _privateKey;
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
	public boolean verifySignature(byte[] cipherDigest, byte[] bytes, byte[] key) throws Exception {
		PublicKey k = ObjectUtil.readObjectBytes(key, PublicKey.class);

		Signature cipher = Signature.getInstance(MAC_SIGNATURE);
		cipher.initVerify(k);
		cipher.update(bytes);

		return cipher.verify(cipherDigest);
	}
}
