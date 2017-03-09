package pm.cli;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import static javax.xml.bind.DatatypeConverter.printHexBinary;


public class SecureClient {
	
	public static final String CIPHER_ALGORITHM = "RSA";
	public static final String HASH_ALGORITHM = "SHA-256";
	private static final String DIGITAL_SIGNATURE = "SHA256withRSA";


	
	public static byte[] cipher(KeyStore ks, String alias, char[] password, byte[] plainTextMessage) throws Exception{
		PublicKey key = getPublicKey(ks, alias, password);

	    // get an RSA cipher object and print the provider
	    final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);
	    // encrypt the plain text using the public key
	    cipher.init(Cipher.ENCRYPT_MODE, key);
	    byte[] cipherText = cipher.doFinal(plainTextMessage);

	    return cipherText;
	}
	
	public static byte[] decipher(KeyStore ks, String alias, char[] password, byte[] cipheredMessage) throws Exception{
		PrivateKey key = getPrivateKey(ks, alias, password);
		
	    byte[] dectyptedText = null;
	    // get an RSA cipher object and print the provider
	    final Cipher cipher = Cipher.getInstance(CIPHER_ALGORITHM);

	    // decrypt the text using the private key
	    cipher.init(Cipher.DECRYPT_MODE, key);
	    dectyptedText = cipher.doFinal(cipheredMessage);

	    return dectyptedText;
	}

    public static byte[] hash(byte[] data) throws NoSuchAlgorithmException {
    	MessageDigest md = MessageDigest.getInstance(HASH_ALGORITHM);
        md.update(data);
        return md.digest();
    }
	
	
	public static PublicKey getPublicKey(KeyStore keystore, String alias, char[] password) throws Exception {
		Key key = keystore.getKey(alias, password);
		if (key instanceof PrivateKey) {
			// Get certificate of public key
			Certificate cert = keystore.getCertificate(alias);

			// Get public key
			PublicKey publicKey = cert.getPublicKey();
			return publicKey;
		}
		throw new Exception("key");
	}
	
	
	public static PrivateKey getPrivateKey(KeyStore keystore, String alias, char[] password) throws Exception {
		PrivateKey key = (PrivateKey) keystore.getKey(alias, password);
		return key;
	}
	
	
	/***********************************
	 * DIGITAL SIGNATURE
	 ***********************************/
	public static byte[] makeSignature(KeyStore keystore, String alias, char[] password, byte[] bytes) throws Exception{
		PrivateKey privateKey = getPrivateKey(keystore, alias, password);
		return makeSignature(privateKey, bytes);
	}
	
	public static boolean verifySignature(KeyStore keystore, String alias, char[] password, byte[] cipherDigest, byte[] bytes) throws Exception{
		PublicKey publicKey = getPublicKey(keystore, alias, password);
		return verifySignature(publicKey, cipherDigest, bytes);
	}
	
	
	public static byte[] makeSignature(PrivateKey privateKey, byte[] bytes) throws Exception {
		Signature cipher = Signature.getInstance(DIGITAL_SIGNATURE);
		cipher.initSign(privateKey);
		cipher.update(bytes);

		return cipher.sign();
	}
	
	public static boolean verifySignature(PublicKey k, byte[] cipherDigest, byte[] bytes) throws Exception {
		Signature cipher = Signature.getInstance(DIGITAL_SIGNATURE);
		cipher.initVerify(k);
		cipher.update(bytes);

		return cipher.verify(cipherDigest);
	}
	
}
