package pm.handler;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import pm.exception.InvalidKeyException;
import pm.exception.InvalidMessageDigestException;

import static javax.xml.bind.DatatypeConverter.printHexBinary;


//Timestamp
import java.sql.Timestamp;

public class HandlerSecurity {

	private PrivateKey _privateKey;
	private PublicKey _publicKey;
	private String keyPath = ".";
	
	
	
	public HandlerSecurity() throws IOException, NoSuchAlgorithmException{
		try{
	        System.out.println("Reading key from file " + keyPath + " ...");
	        byte[] keyBytesPublic = Files.readAllBytes(new File(keyPath + "/ServerPublic.key").toPath());
	        X509EncodedKeySpec specPublic = new X509EncodedKeySpec(keyBytesPublic);
	        KeyFactory kf = KeyFactory.getInstance("RSA");
	        _publicKey = kf.generatePublic(specPublic);
			
	        System.out.println("Reading key from file " + keyPath + " ...");
	        byte[] keyBytesPrivate = Files.readAllBytes(new File(keyPath + "/ServerPrivate.key").toPath());
	        PKCS8EncodedKeySpec specPrivate = new PKCS8EncodedKeySpec(keyBytesPrivate);
	        _privateKey = kf.generatePrivate(specPrivate);
		}
		catch(Exception e){
			System.out.println("Generating RSA key ..." );
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

	        System.out.println("Writing Private key to '" + keyPath + "' ..." );
	        FileOutputStream privFos = new FileOutputStream(keyPath + "/ServerPrivate.key");
	        privFos.write(privKeyEncoded);
	        privFos.close();
	        System.out.println("Writing Pubic key to '" + keyPath + "' ..." );
	        FileOutputStream pubFos = new FileOutputStream(keyPath + "/ServerPublic.key");
	        pubFos.write(pubKeyEncoded);
	        pubFos.close();        
		}
	}
	
	
	public PublicKey getPublicKey(){
		return _publicKey;
	}
	
	private PrivateKey getPrivateKey(){
		return _privateKey;
	}
	
	/*
	 * Check if time is within limits?
	 * If yes: Check if nonce already exists?
	 *         if yes: discards message
	 *         If Not: 
	 */
	
	
    /** auxiliary method to make the MAC */
    public byte[] makeSignature(byte[] bytes) throws Exception {
    	PrivateKey privateKey = getPrivateKey();
    	Signature cipher = Signature.getInstance("SHA256withRSA");
    	cipher.initSign(privateKey);
        cipher.update(bytes);

        return cipher.sign();
    }

    /** auxiliary method to calculate new digest from text and compare it to the
         to deciphered digest */
    public boolean verifySignature(byte[] cipherDigest,
    								byte[] bytes, 
    								byte[] key) throws Exception {
    	PublicKey k = (PublicKey) keyToKey(key);
        Signature cipher = Signature.getInstance("SHA256withRSA");
        cipher.initVerify(k);
        cipher.update(bytes);
        
        return cipher.verify(cipherDigest);
	}
    
	

    public Key generateKey() throws GeneralSecurityException, IOException {
        // get an AES private key
        System.out.println("Generating AES key ..." );
        KeyGenerator keyGen = KeyGenerator.getInstance("AES");
        keyGen.init(256);
        Key key = keyGen.generateKey();
        System.out.println( "Finish generating AES key" );
        byte[] encoded = key.getEncoded();
        System.out.println("Key:");
        System.out.println(printHexBinary(encoded));
        return key;
    }
	
	
    private java.security.Key keyToKey(byte[] k) throws Exception {
		try{
			ByteArrayInputStream bis = new ByteArrayInputStream(k);
			ObjectInput in = new ObjectInputStream(bis);
			java.security.Key key = (java.security.Key) in.readObject();
			in.close();
			bis.close();
			return key;
		}
		catch(Exception e){
			throw e;
		}
	}
    
    
    
    // - DIGEST - //
    public static MessageDigest object2Hash(MessageDigest md, Object obj) throws NoSuchAlgorithmException, IOException {
        
        if (md == null) {
            md = MessageDigest.getInstance("SHA-256");
        }
        md.update(object2Bytes(obj));
        return md;
    }

    public static byte[] digestMessage(MessageDigest md) throws InvalidMessageDigestException {

        if (md == null) {
            throw new InvalidMessageDigestException(); // needs to be corrected
        }
        return md.digest();
    }

    private static byte[] object2Bytes(Object obj) throws IOException{

        // Convert Object To bytes!
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        ObjectOutput out = new ObjectOutputStream(bos);
        out.writeObject(obj);
        out.flush();

        return bos.toByteArray();
    }

    //useless but if needed is created!
    private static Object byte2Object(byte[] byt) throws Exception {
        ByteArrayInputStream bis = new ByteArrayInputStream(byt);
        ObjectInput in = new ObjectInputStream(bis);

        return in.readObject();
    }
    
    // - KEY PART - 
}
