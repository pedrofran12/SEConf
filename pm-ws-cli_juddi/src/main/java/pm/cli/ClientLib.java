package pm.cli;

import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static javax.xml.bind.DatatypeConverter.printHexBinary;

import java.security.Key;
import java.security.KeyStore;

import pm.exception.cli.AlreadyExistsLoggedUserException;
import pm.exception.cli.NoSessionException;
import pm.handler.ClientHandler;
import pm.ws.PasswordManager;
import utilities.ObjectUtil;

public class ClientLib {
	private PasswordManager _pm;
	private KeyStore _ks;
	private String _alias;
	private char[] _password;

	
	public ClientLib(PasswordManager port) {
		_pm = port;
	}

	public void init(KeyStore ks, String alias, char[] password) throws AlreadyExistsLoggedUserException {
		if(isSessionAlive())
			throw new AlreadyExistsLoggedUserException();
		setKeyStore(ks);
		setKeyStoreAlias(alias);
		setKeyStorePassword(password);
		ClientHandler.setHandler(ks, alias, password);
	}

	public void register_user() throws Exception {
		if(!isSessionAlive())
			throw new NoSessionException();
		pm.ws.Key k = getPublicKey();
		_pm.register(k);
	}

	public void save_password(byte[] domain, byte[] username, byte[] password){
    	try {
    		if(!isSessionAlive())
    			throw new NoSessionException();
    		byte[] hashedDomain = hash(domain);
    		byte[] hashedUsername = hash(domain, username);
    		byte[] cipheredPassword = cipher(password);
    		_pm.put(getPublicKey(), hashedDomain, hashedUsername, cipheredPassword);
    	} catch (Exception pme) {
    		pme.printStackTrace();
    	}
    }

  public byte[] retrieve_password(byte[] domain, byte[] username){
      byte[] password = null;
      
      try{
	  		if(!isSessionAlive())
	  			throw new NoSessionException();
    		byte[] hashedDomain = hash(domain);
    		byte[] hashedUsername = hash(domain, username);
     		byte[] passwordCiphered = _pm.get(getPublicKey(), hashedDomain, hashedUsername);
    		password = decipher(passwordCiphered);
      }catch(Exception pme){
          pme.printStackTrace();
      }

      return password;
  }
  
	public void close() {
		setKeyStore(null);
		setKeyStoreAlias(null);
		setKeyStorePassword(null);
	}
  
	private KeyStore getKeyStore() {
		return _ks;
	}
	
	
	private boolean isSessionAlive(){
		return getKeyStore()!=null && getKeyStoreAlias()!=null && getKeyStorePassword()!=null;
	}

	private pm.ws.Key getPublicKey() throws Exception {
		KeyStore keystore = getKeyStore();
		String alias = getKeyStoreAlias();
		char[] password = getKeyStorePassword();
		Key publicKey = SecureClient.getPublicKey(keystore, alias, password);
		
		
		pm.ws.Key k = new pm.ws.Key();
		k.setKey(ObjectUtil.writeObjectBytes(publicKey));
		return k;
	}
	
	private pm.ws.Key getPrivateKey() throws Exception {
		KeyStore keystore = getKeyStore();
		String alias = getKeyStoreAlias();
		char[] password = getKeyStorePassword();
		Key publicKey = SecureClient.getPrivateKey(keystore, alias, password);
		
		
		pm.ws.Key k = new pm.ws.Key();
		k.setKey(ObjectUtil.writeObjectBytes(publicKey));
		return k;
	}
	
	private byte[] cipher(byte[] plainText) throws Exception{
  		KeyStore ks = getKeyStore();
  		String ksAlias = getKeyStoreAlias();
  		char[] ksPassword = getKeyStorePassword();
		
  		byte[] cipheredPlainText = SecureClient.cipher(ks, ksAlias, ksPassword, plainText);
  		return cipheredPlainText;
	}

	
	private byte[] decipher(byte[] cipheredPlainText) throws Exception{
  		KeyStore ks = getKeyStore();
  		String ksAlias = getKeyStoreAlias();
  		char[] ksPassword = getKeyStorePassword();
		
  		byte[] plainText = SecureClient.decipher(ks, ksAlias, ksPassword, cipheredPlainText);
  		return plainText;
	}
	
	private byte[] hash(byte[]... data) throws Exception{
		String dataToHash = "";
		for(byte[] b : data)
			dataToHash += printHexBinary(b);
		dataToHash += printHexBinary(getPrivateKey().getKey());
		
		byte[] hash = SecureClient.hash(parseHexBinary(dataToHash));
		return hash;
	}
	
	private void setKeyStore(KeyStore k) {
		_ks = k;
	}

	private void setKeyStoreAlias(String alias) {
		_alias = alias;
	}

	private void setKeyStorePassword(char[] password) {
		_password = password;
	}

	private String getKeyStoreAlias() {
		return _alias;
	}

	private char[] getKeyStorePassword() {
		return _password;
	}
}
