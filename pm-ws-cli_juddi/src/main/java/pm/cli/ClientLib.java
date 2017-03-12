package pm.cli;

import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static javax.xml.bind.DatatypeConverter.printHexBinary;

import java.security.Key;
import java.security.KeyStore;

import pm.exception.cli.*;
import pm.handler.ClientHandler;
import pm.ws.InvalidKeyException_Exception;
import pm.ws.KeyAlreadyExistsException_Exception;
import pm.ws.PasswordManager;
import pm.ws.PasswordManagerException_Exception;
import utilities.ObjectUtil;

public class ClientLib {
	private PasswordManager _pm;
	private KeyStore _ks;
	private String _alias;
	private char[] _password;

	public ClientLib(PasswordManager port) {
		_pm = port;
	}

	public void init(KeyStore ks, String alias, char[] password) throws ClientException{
		if (isSessionAlive())
			throw new AlreadyExistsLoggedUserException();
		if(ks==null || alias == null || password == null)
		    throw new InvalidKeyStoreException();
		setKeyStore(ks);
		setKeyStoreAlias(alias);
		setKeyStorePassword(password);
		ClientHandler.setHandler(ks, alias, password);
	}

	public void register_user() throws ClientException, InvalidKeyException_Exception, KeyAlreadyExistsException_Exception {
		if (!isSessionAlive())
			throw new NoSessionException();
		pm.ws.Key k = getPublicKey();
		_pm.register(k);
	}

	public void save_password(byte[] domain, byte[] username, byte[] password)
			throws PasswordManagerException_Exception, ClientException {
		if (!isSessionAlive())
			throw new NoSessionException();
		if(domain==null)
		    throw new InvalidDomainException();
		if(username==null)
		    throw new InvalidUsernameException();
		if(password==null)
		    throw new InvalidPasswordException();
		byte[] hashedDomain = hash(domain);
		byte[] hashedUsername = hash(domain, username);
		byte[] cipheredPassword = cipher(password);
		_pm.put(getPublicKey(), hashedDomain, hashedUsername, cipheredPassword);
	}

	public byte[] retrieve_password(byte[] domain, byte[] username)
			throws PasswordManagerException_Exception, ClientException {
		if (!isSessionAlive())
			throw new NoSessionException();
		if(domain==null)
            throw new InvalidDomainException();
        if(username==null)
            throw new InvalidUsernameException();
		byte[] hashedDomain = hash(domain);
		byte[] hashedUsername = hash(domain, username);
		byte[] passwordCiphered = _pm.get(getPublicKey(), hashedDomain, hashedUsername);
		byte[] password = decipher(passwordCiphered);

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

	private boolean isSessionAlive() {
		return getKeyStore() != null && getKeyStoreAlias() != null && getKeyStorePassword() != null;
	}

	private pm.ws.Key getPublicKey() throws InvalidKeyStoreException {
		try {
			KeyStore keystore = getKeyStore();
			String alias = getKeyStoreAlias();
			char[] password = getKeyStorePassword();
			Key publicKey = SecureClient.getPublicKey(keystore, alias, password);

			pm.ws.Key k = new pm.ws.Key();
			k.setKey(ObjectUtil.writeObjectBytes(publicKey));
			return k;
		} catch (Exception e) {
			throw new InvalidKeyStoreException();
		}
	}

	private pm.ws.Key getPrivateKey() throws InvalidKeyStoreException {
		try {
			KeyStore keystore = getKeyStore();
			String alias = getKeyStoreAlias();
			char[] password = getKeyStorePassword();
			Key publicKey = SecureClient.getPrivateKey(keystore, alias, password);

			pm.ws.Key k = new pm.ws.Key();
			k.setKey(ObjectUtil.writeObjectBytes(publicKey));
			return k;
		} catch (Exception e) {
			throw new InvalidKeyStoreException();
		}
	}

	private byte[] cipher(byte[] plainText) {
		KeyStore ks = getKeyStore();
		String ksAlias = getKeyStoreAlias();
		char[] ksPassword = getKeyStorePassword();

		byte[] cipheredPlainText = null;
		try {
			cipheredPlainText = SecureClient.cipher(ks, ksAlias, ksPassword, plainText);
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
		}
		return cipheredPlainText;
	}

	private byte[] decipher(byte[] cipheredPlainText) {
		KeyStore ks = getKeyStore();
		String ksAlias = getKeyStoreAlias();
		char[] ksPassword = getKeyStorePassword();

		byte[] plainText = null;
		try {
			plainText = SecureClient.decipher(ks, ksAlias, ksPassword, cipheredPlainText);
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
		}
		return plainText;
	}

	private byte[] hash(byte[]... data) throws InvalidKeyStoreException {
		String dataToHash = "";
		for (byte[] b : data)
			dataToHash += printHexBinary(b);
		dataToHash += printHexBinary(getPrivateKey().getKey());

		byte[] hash = null;
		try {
			hash = SecureClient.hash(parseHexBinary(dataToHash));
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
		}
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
