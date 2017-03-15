package pm.cli;

import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static javax.xml.bind.DatatypeConverter.printHexBinary;

import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyStore;
import java.util.Arrays;

import pm.exception.cli.AlreadyExistsLoggedUserException;
import pm.exception.cli.ClientException;
import pm.exception.cli.InvalidDomainException;
import pm.exception.cli.InvalidKeyStoreException;
import pm.exception.cli.InvalidPasswordException;
import pm.exception.cli.InvalidUsernameException;
import pm.exception.cli.NoSessionException;
import pm.handler.ClientHandler;
import pm.ws.InvalidDomainException_Exception;
import pm.ws.InvalidKeyException_Exception;
import pm.ws.InvalidPasswordException_Exception;
import pm.ws.InvalidUsernameException_Exception;
import pm.ws.KeyAlreadyExistsException_Exception;
import pm.ws.PasswordManager;
import pm.ws.UnknownUsernameDomainException_Exception;
import utilities.ObjectUtil;

public class ClientLib {
	private PasswordManager _pm;
	private KeyStore _ks;
	private String _alias;
	private char[] _password;

	public ClientLib(PasswordManager port) {
		_pm = port;
	}

	public void init(KeyStore ks, String alias, char[] password) throws ClientException {
		if (isSessionAlive())
			throw new AlreadyExistsLoggedUserException();
		if (ks == null || alias == null || password == null)
			throw new InvalidKeyStoreException();
		setKeyStore(ks);
		setKeyStoreAlias(alias);
		setKeyStorePassword(password);
		ClientHandler.setHandler(ks, alias, password);
	}

	public void register_user()
			throws ClientException, InvalidKeyException_Exception, KeyAlreadyExistsException_Exception {
		if (!isSessionAlive())
			throw new NoSessionException();
		pm.ws.Key k = getPublicKey();
		_pm.register(k);
	}

	public void save_password(byte[] domain, byte[] username, byte[] password)
			throws InvalidKeyException_Exception, InvalidDomainException_Exception, InvalidUsernameException_Exception,
			InvalidPasswordException_Exception, ClientException {
		if (!isSessionAlive())
			throw new NoSessionException();
		if (domain == null)
			throw new InvalidDomainException();
		if (username == null)
			throw new InvalidUsernameException();
		if (password == null)
			throw new InvalidPasswordException();
		byte[] hashedDomain = hash(domain);
		byte[] hashedUsername = hash(domain, username);
		byte[] hashedPassword = passwordHash(password, domain, username);
		byte[] cipheredPassword = cipher(hashedPassword);
		_pm.put(getPublicKey(), hashedDomain, hashedUsername, cipheredPassword);
	}

	public byte[] retrieve_password(byte[] domain, byte[] username)
			throws InvalidKeyException_Exception, InvalidDomainException_Exception, InvalidUsernameException_Exception,
			UnknownUsernameDomainException_Exception, ClientException {
		if (!isSessionAlive())
			throw new NoSessionException();
		if (domain == null)
			throw new InvalidDomainException();
		if (username == null)
			throw new InvalidUsernameException();
		byte[] hashedDomain = hash(domain);
		byte[] hashedUsername = hash(domain, username);
		byte[] passwordCiphered = _pm.get(getPublicKey(), hashedDomain, hashedUsername);
		byte[] hashedPassword = decipher(passwordCiphered);
		byte[] password = Arrays.copyOfRange(hashedPassword, 256/Byte.SIZE, hashedPassword.length);
		if (!Arrays.equals(passwordHash(password, domain, username), hashedPassword)) {
			throw new InvalidPasswordException();
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
	
	private byte[] passwordHash(byte[] password, byte[] domain, byte[] username) throws InvalidKeyStoreException {
		ByteBuffer bb = ByteBuffer.allocate(password.length + 256/Byte.SIZE);
		bb.put(hash(password, domain, username));
		bb.put(password);
		return bb.array();
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
