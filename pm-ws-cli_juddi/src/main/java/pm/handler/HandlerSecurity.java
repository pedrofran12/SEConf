package pm.handler;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutput;
import java.io.ObjectOutputStream;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.Certificate;
import java.util.Arrays;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.ws.handler.soap.SOAPMessageContext;

import pm.ws.*;

import static javax.xml.bind.DatatypeConverter.printHexBinary;


public class HandlerSecurity {

	private PrivateKey _privateKey;
	private PublicKey _publicKey;
	private String keyPath = ".";
	
	
	public HandlerSecurity() throws IOException, NoSuchAlgorithmException{
		try{
	        //Key do cliente
	        String alias = "client";
			char[] password = "benfica".toCharArray();
			KeyStore ks = KeyStore.getInstance("JKS");
			InputStream readStream = new FileInputStream("src/main/resources/KeyStore.jks");
			ks.load(readStream, password);
			_privateKey = (PrivateKey) ks.getKey(alias, password);
	        readStream.close();
		}
		catch(Exception e){
		}
	}
	
	
	public PublicKey getPublicKey(){
		return _publicKey;
	}
	
	private PrivateKey getPrivateKey(){
		return _privateKey;
	}
	
	
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
			in.close();
			bis.close();
			return (java.security.Key) in.readObject();
		}
		catch(Exception e){
			throw new Exception();
		}
	}
    
    
    
    // - DIGEST - //
	/*
	 * public static MessageDigest object2Hash(MessageDigest md, Object obj) throws NoSuchAlgorithmException, IOException {
        
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
    */
    // - KEY PART - 
}
