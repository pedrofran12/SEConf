package pm.cli;

import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static javax.xml.bind.DatatypeConverter.printHexBinary;

import java.security.KeyStore;
import java.util.List;

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

public class ClientLib extends ClientLibReplicated {

	
	public ClientLib(List<PasswordManager> pmList, int f) {
		super(pmList, f);
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
		
		register();
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
		byte[] cipheredPassword = cipher(password);
		int wid = -1;
		try {
			GetResponseWrapper wrap = get(hashedDomain, hashedUsername);
			wid = wrap.getWid();
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		put(hashedDomain, hashedUsername, cipheredPassword, ++wid);
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
		
		GetResponseWrapper response = get(hashedDomain, hashedUsername);
		byte[] passwordCiphered = response.getPassword();
		String widForm = response.getWidForm();
		try {
			put(hashedDomain, hashedUsername, passwordCiphered, widForm);
		} catch (Exception e) {
			e.printStackTrace();
		}
		
		// check password integrity
		byte[] password;
		try{
			password = decipher(passwordCiphered);
		}catch(Exception e){
			throw new InvalidPasswordException();
		}
		return password;
	}

	public void close() {
		setKeyStore(null);
		setKeyStoreAlias(null);
		setKeyStorePassword(null);
	}


	private boolean isSessionAlive() {
		return getKeyStore() != null && getKeyStoreAlias() != null && getKeyStorePassword() != null;
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
		dataToHash += printHexBinary(getPrivateKey().getEncoded());

		byte[] hash = null;
		try {
			hash = SecureClient.hash(parseHexBinary(dataToHash));
		} catch (Exception e) {
			System.out.println("Exception: " + e.getMessage());
		}
		return hash;
	}
}
