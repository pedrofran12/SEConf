package pm.cli;

import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static javax.xml.bind.DatatypeConverter.printHexBinary;

import java.nio.ByteBuffer;
import java.security.Key;
import java.security.KeyStore;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import javax.xml.ws.BindingProvider;
import javax.xml.ws.Response;

import com.sun.xml.ws.client.ClientTransportException;

import pm.exception.cli.AlreadyExistsLoggedUserException;
import pm.exception.cli.ClientException;
import pm.exception.cli.InsufficientResponsesException;
import pm.exception.cli.InvalidDomainException;
import pm.exception.cli.InvalidKeyStoreException;
import pm.exception.cli.InvalidPasswordException;
import pm.exception.cli.InvalidUsernameException;
import pm.exception.cli.NoSessionException;
import pm.handler.ClientHandler;
import pm.ws.GetResponse;
import pm.ws.InvalidDomainException_Exception;
import pm.ws.InvalidKeyException_Exception;
import pm.ws.InvalidPasswordException_Exception;
import pm.ws.InvalidUsernameException_Exception;
import pm.ws.KeyAlreadyExistsException_Exception;
import pm.ws.PasswordManager;
import pm.ws.PutResponse;
import pm.ws.RegisterResponse;
import pm.ws.UnknownUsernameDomainException_Exception;
import utilities.ObjectUtil;

public class ClientLib {
	private static final long WAITING_TIME = 30 * 1000;
	private List<PasswordManager> _pmList = new ArrayList<>();
	private KeyStore _ks;
	private String _alias;
	private char[] _password;
	
	private int number_tolerating_faults;
	
	
	private int wts = 0;

/*	
	public ClientLib(PasswordManager port) {
		_pm = port;
	}
	*/
	public ClientLib(List<PasswordManager> pmList, int f) {
		_pmList = pmList;
		number_tolerating_faults = f;
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
		
		ArrayList<Response<RegisterResponse>> responsesList = new ArrayList<Response<RegisterResponse>>();
		for(PasswordManager pm : _pmList)
			responsesList.add(pm.registerAsync(k));
		
		boolean success = false;
		int numberResponses = 0;
		ExecutionException exception = null;
		long current = System.currentTimeMillis();
		while(numberResponses < 2*number_tolerating_faults + 1){
			// to see exception
			if (System.currentTimeMillis() - current > WAITING_TIME || // waiting time exceeded
					responsesList.isEmpty()) { // no more servers to communicate
				throw new InsufficientResponsesException();
			}
			
	        for(Response<RegisterResponse> r : responsesList){
	        	if(r.isDone()){
	        		try {
	                	//testar se Resposta e excepcao
						r.get();
						success = true;	
						numberResponses++;
	                }
	        		catch (ClientTransportException e) {
	        			System.out.println("Caught execution exception.");
	                    System.out.print("Cause: ");
	                    System.out.println(e.getMessage());
	                    e.printStackTrace();
	        		}
	                catch (ExecutionException e1) {
	                	if (!(e1.getCause() instanceof ClientTransportException)) {
	                		numberResponses++;
	                		exception = e1;
	                	} else {
	                		e1.printStackTrace();
	                	}
	                }
	                catch (Exception e) {
	                    System.out.println("Caught execution exception.");
	                    System.out.print("Cause: ");
	                    System.out.println(e.getMessage());
	                    e.printStackTrace();
	                }
	                responsesList.remove(r);
	                break;
	        	}
	        }
		}
		if(!success) {
			if (exception.getCause() instanceof InvalidKeyException_Exception)
				throw (InvalidKeyException_Exception) exception.getCause();
			else if (exception.getCause() instanceof KeyAlreadyExistsException_Exception)
				throw (KeyAlreadyExistsException_Exception) exception.getCause();
			else {
				exception.printStackTrace();
			}
		}
		
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
		
		ArrayList<Response<PutResponse>> responsesList = new ArrayList<Response<PutResponse>>();
		int wid = wts++;
		for(PasswordManager pm : _pmList){
			BindingProvider bindingProvider = (BindingProvider) pm;
			Map<String, Object> requestContext = bindingProvider.getRequestContext();
			// put token in request context
			System.out.printf("put token '%d' on request context%n", wid);
			requestContext.put(ClientHandler.WRITE_IDENTIFIER_RESPONSE_PROPERTY, wid);
			responsesList.add(pm.putAsync(getPublicKey(), hashedDomain, hashedUsername, cipheredPassword));
		}

		boolean success = false;
		int numberResponses = 0;
		ExecutionException exception = null;
		long current = System.currentTimeMillis();
		while(numberResponses < 2*number_tolerating_faults + 1){
			// to see exception
			if (System.currentTimeMillis() - current > WAITING_TIME || // waiting time exceeded
					responsesList.isEmpty()) { // no more servers to communicate
				throw new InsufficientResponsesException();
			}
			
	        for(Response<PutResponse> r : responsesList){
	        	if(r.isDone()){
	        		try {
	                	//testar se Resposta e excepcao
						r.get();
						success = true;	
						numberResponses++;
	                }
	        		catch (ClientTransportException e) {
	        			System.out.println("Caught execution exception.");
	                    System.out.print("Cause: ");
	                    System.out.println(e.getMessage());
	                    e.printStackTrace();
	        		}
	                catch (ExecutionException e1) {
	                	if (!(e1.getCause() instanceof ClientTransportException)) {
	                		numberResponses++;
	                		exception = e1;
	                	} else {
	                		e1.printStackTrace();
	                	}
	                }
	                catch (Exception e) {
	                    System.out.println("Caught execution exception.");
	                    System.out.print("Cause: ");
	                    System.out.println(e.getMessage());
	                    e.printStackTrace();
	                }
	                responsesList.remove(r);
	                break;
	        	}
	        }
		}
		if(!success) {
			if (exception.getCause() instanceof InvalidKeyException_Exception)
				throw (InvalidKeyException_Exception) exception.getCause();
			else if (exception.getCause() instanceof InvalidDomainException_Exception)
				throw (InvalidDomainException_Exception) exception.getCause();
			else if (exception.getCause() instanceof InvalidUsernameException_Exception)
				throw (InvalidUsernameException_Exception) exception.getCause();
			else if (exception.getCause() instanceof InvalidPasswordException_Exception)
				throw (InvalidPasswordException_Exception) exception.getCause();
			else {
				exception.printStackTrace();
			}
		}
		
		//_pm.put(getPublicKey(), hashedDomain, hashedUsername, cipheredPassword);
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

		ArrayList<Response<GetResponse>> responsesList = new ArrayList<Response<GetResponse>>();
		for(PasswordManager pm : _pmList)
			responsesList.add(pm.getAsync(getPublicKey(), hashedDomain, hashedUsername));
		
		int numberResponses = 0;
        int latestTag = -1;
        byte[] lastVersionContent = ("").getBytes();
        ExecutionException exception = null;
        long current = System.currentTimeMillis();
		while(numberResponses < 2*number_tolerating_faults + 1){
			// to see exception
			if (System.currentTimeMillis() - current > WAITING_TIME || // waiting time exceeded
					responsesList.isEmpty()) { // no more servers to communicate
				throw new InsufficientResponsesException();
			}
	        for(Response<GetResponse> r : responsesList){
	        	if(r.isDone()){
	                try {
	                	//testar se Resposta e excepcao
						r.get();
						numberResponses++;
		        		// access request context
		        		Map<String, Object> responseContext = r.getContext();

	                	byte[] content = r.get().getReturn().getValue();
	                    System.out.println("Asynchronous call result: " + printHexBinary(r.get().getReturn().getValue()));

	                    // get token from message context
	                    int wid = (int) responseContext.get(ClientHandler.WRITE_IDENTIFIER_RESPONSE_PROPERTY);
	                    System.out.printf("got token '%d' from response context%n", wid);

	                    if(wid > latestTag){
	                    	latestTag = wid;
	                    	lastVersionContent = content;
	                    }
	                }
	                catch (ExecutionException e1) {
	                	if (!(e1.getCause() instanceof ClientTransportException)) {
	                		numberResponses++;
	                		exception = e1;
	                	} else {
	                		e1.printStackTrace();
	                	}
	                }
	                catch (Exception e) {
	                    System.out.println("Caught execution exception.");
	                    System.out.print("Cause: ");
	                    System.out.println(e.getCause());
	                }
	                responsesList.remove(r);
	                break;
	        	}
	        }
		}
		if(latestTag==-1) {
			if (exception.getCause() instanceof InvalidKeyException_Exception)
				throw (InvalidKeyException_Exception) exception.getCause();
			else if (exception.getCause() instanceof InvalidDomainException_Exception)
				throw (InvalidDomainException_Exception) exception.getCause();
			else if (exception.getCause() instanceof InvalidUsernameException_Exception)
				throw (InvalidUsernameException_Exception) exception.getCause();
			else if (exception.getCause() instanceof UnknownUsernameDomainException_Exception)
				throw (UnknownUsernameDomainException_Exception) exception.getCause();
			else
				exception.printStackTrace();
		}
		
		//byte[] passwordCiphered = _pm.get(getPublicKey(), hashedDomain, hashedUsername);
		byte[] passwordCiphered = lastVersionContent;
				//_pmList.get(0).get(getPublicKey(), hashedDomain, hashedUsername);
		byte[] password;
		try{
			byte[] hashedPassword = decipher(passwordCiphered);
			password = Arrays.copyOfRange(hashedPassword, 256/Byte.SIZE, hashedPassword.length);
			if (!Arrays.equals(passwordHash(password, domain, username), hashedPassword)) {
				throw new InvalidPasswordException();
			}
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
