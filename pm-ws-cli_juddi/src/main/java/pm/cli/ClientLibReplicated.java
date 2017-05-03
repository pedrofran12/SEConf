package pm.cli;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

import java.io.ByteArrayOutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import javax.xml.ws.BindingProvider;
import javax.xml.ws.Response;

import com.sun.xml.ws.client.ClientTransportException;

import pm.exception.cli.AlreadyExistsLoggedUserException;
import pm.exception.cli.ClientException;
import pm.exception.cli.InsufficientResponsesException;
import pm.exception.cli.InvalidKeyStoreException;
import pm.exception.cli.InvalidPasswordException;
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

public abstract class ClientLibReplicated {
	public static final long WAITING_TIME = 30 * 1000;
	private static final String WID_SEPARATOR = ":";
	
	private final List<PasswordManager> _pmList;
	private final int number_tolerating_faults;
	private final int tieBreaker;

	private KeyStore _ks;
	private String _alias;
	private char[] _password;
	
	
	public ClientLibReplicated(List<PasswordManager> pmList, int nFaults) {
		_pmList = pmList;
		number_tolerating_faults = nFaults;
		tieBreaker = new SecureRandom().nextInt(Integer.MAX_VALUE);
	}
	
	/*protected void setSymmetricKey(KeyStore keystore, String alias, char[] password) throws InvalidKeyStoreException {
		try {
			symmetricKey = SecureClient.getSymmetricKey(keystore, alias, password);
		} catch (Exception e) {
			throw new InvalidKeyStoreException();
		}
	}*/
	
	// replicated register
	public void register() throws InsufficientResponsesException,
			InvalidKeyException_Exception, KeyAlreadyExistsException_Exception, InvalidKeyStoreException {
		
		ArrayList<Response<RegisterResponse>> responsesList = new ArrayList<Response<RegisterResponse>>();
		for(PasswordManager pm : _pmList)
			responsesList.add(pm.registerAsync(getPublicKeyToSend()));
		
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
	
	
	// replicated put
	public void put(byte[] domain, byte[] username, byte[] password, int wid)
			throws InsufficientResponsesException, InvalidKeyException_Exception,
			InvalidDomainException_Exception, InvalidUsernameException_Exception,
			InvalidPasswordException_Exception, InvalidKeyStoreException {
		
		// create wid signature
		//String widMac = makeMac(wid, tieBreaker, domain, username, password);
		String widSignature = makeSignature(wid, tieBreaker, domain, username, password);
		
		//String widForm = wid + WID_SEPARATOR + tieBreaker + WID_SEPARATOR + widMac;
		String widForm = wid + WID_SEPARATOR + tieBreaker + WID_SEPARATOR + widSignature;
		put(domain, username, password, widForm);
	}
	
	public void put(byte[] domain, byte[] username, byte[] password, String widForm)
			throws InsufficientResponsesException, InvalidKeyException_Exception,
			InvalidDomainException_Exception, InvalidUsernameException_Exception,
			InvalidPasswordException_Exception, InvalidKeyStoreException {
		
		ArrayList<Response<PutResponse>> responsesList = new ArrayList<Response<PutResponse>>();
		for(PasswordManager pm : _pmList){
			BindingProvider bindingProvider = (BindingProvider) pm;
			Map<String, Object> requestContext = bindingProvider.getRequestContext();
			// put token in request context
			System.out.printf("put token '%s' on request context%n", widForm);
			requestContext.put(ClientHandler.WRITE_IDENTIFIER_RESPONSE_PROPERTY, widForm);
			responsesList.add(pm.putAsync(getPublicKeyToSend(), domain, username, password));
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
	}
	
	
	// replicated get
	public GetResponseWrapper get(byte[] domain, byte[] username) throws InsufficientResponsesException,
			InvalidKeyException_Exception, InvalidDomainException_Exception, InvalidUsernameException_Exception,
			UnknownUsernameDomainException_Exception, InvalidPasswordException, InvalidKeyStoreException {
		
		ArrayList<Response<GetResponse>> responsesList = new ArrayList<Response<GetResponse>>();
		for(PasswordManager pm : _pmList)
			responsesList.add(pm.getAsync(getPublicKeyToSend(), domain, username));
		
		int numberResponses = 0;
        int latestTag = -1;
        int latestTie = Integer.MIN_VALUE;
        String lastestForm = latestTag + WID_SEPARATOR + latestTie;
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
		        		// access request context
		        		Map<String, Object> responseContext = r.getContext();

	                	byte[] content = r.get().getReturn().getValue();
	                    System.out.println("Asynchronous call result: " + printHexBinary(r.get().getReturn().getValue()));

	                    // get token from message context
	                    String widForm = (String) responseContext.get(ClientHandler.WRITE_IDENTIFIER_RESPONSE_PROPERTY);
	                    String[] splited = widForm.split(WID_SEPARATOR, 3);;
	                    int wid = Integer.parseInt(splited[0]);
	                    int tie = Integer.parseInt(splited[1]);
	                    //String widMac = splited[2];
	                    String widSignature = splited[2];
	                    
	                    // verify signature
	                    //if (!verifyMac(widMac, wid, tie, domain, username, content))
	                    if (!verifySignature(widSignature, wid, tie, domain, username, content))
	                    	throw new ExecutionException(new InvalidPasswordException());
	                    
	                    System.out.printf("got token '%d' from response context%n", wid);

	                    if(wid > latestTag || (wid == latestTag && tie > latestTie)){
	                    	lastestForm = widForm;
	                    	latestTag = wid;
	                    	latestTie = tie;
	                    	lastVersionContent = content;
	                    }
	                    numberResponses++;
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
			else if (exception.getCause() instanceof InvalidPasswordException)
				throw (InvalidPasswordException) exception.getCause();
			else
				throw new InvalidPasswordException();
		}
		
		return new GetResponseWrapper(lastVersionContent, lastestForm);
	}
	
	private byte[] generateFormWidMac(int wid, int tie, byte[]... values) {
		String toMake = wid + WID_SEPARATOR + tie;
		for (byte[] value : values) {
			toMake += WID_SEPARATOR + Base64.getEncoder().encodeToString(value);
		}
		return toMake.getBytes();
	}
	
	/*private String makeMac(int wid, int tie, byte[]... values) {
		try {
			byte[] bytesForMac = generateFormWidMac(wid, tie, values);
			byte[] mac = SecureClient.makeMAC(symmetricKey, bytesForMac);
			return Base64.getEncoder().encodeToString(mac);
		} catch (Exception e) {
			return null;
		}
	}
	
	private boolean verifyMac(String macString, int wid, int tie, byte[]... values) {
		try {
			byte[] bytesForMac = generateFormWidMac(wid, tie, values);
			byte[] mac = Base64.getDecoder().decode(macString);
			return SecureClient.verifyMAC(symmetricKey, mac, bytesForMac);
		} catch (Exception e) {
			return false;
		}
	}*/
	
	
	
	private String makeSignature(int wid, int tie, byte[]... values) {
		try {
			//byte[] bytesForMac = generateFormWidMac(wid, tie, values);
			byte[] bytesForSignature = generateFormWidMac(wid, tie, values);
			byte[] signature = SecureClient.makeSignature(getPrivateKey(), bytesForSignature);
			return Base64.getEncoder().encodeToString(signature);
		} catch (Exception e) {
			return null;
		}
	}
	
	private boolean verifySignature(String signatureString, int wid, int tie, byte[]... values) {
		try {
			//byte[] bytesForMac = generateFormWidMac(wid, tie, values);
			byte[] bytesForSignature = generateFormWidMac(wid, tie, values);
			//byte[] mac = Base64.getDecoder().decode(macString);
			byte[] signature = Base64.getDecoder().decode(signatureString);
			//return SecureClient.verifyMAC(symmetricKey, mac, bytesForMac);
			return SecureClient.verifySignature(getPublicKey(), signature, bytesForSignature);
		} catch (Exception e) {
			return false;
		}
	}
	
	
	public class GetResponseWrapper {
		private final byte[] password;
		private final String widForm;
		private final int wid;
		private final int tie;
		public GetResponseWrapper(byte[] p, String w) {
			password = p;
			widForm = w;
			String[] splited = widForm.split(WID_SEPARATOR);
            wid = Integer.parseInt(splited[0]);
            tie = Integer.parseInt(splited[1]);
		}
		public byte[] getPassword() {
			return password;
		}
		public String getWidForm() {
			return widForm;
		}
		public int getWid() {
			return wid;
		}
		public int getTie() {
			return tie;
		}
	}
	
	
	
	protected void setKeyStore(KeyStore k) {
		_ks = k;
	}

	protected void setKeyStoreAlias(String alias) {
		_alias = alias;
	}

	protected void setKeyStorePassword(char[] password) {
		_password = password;
	}

	protected String getKeyStoreAlias() {
		return _alias;
	}

	protected char[] getKeyStorePassword() {
		return _password;
	}
	
	protected PublicKey getPublicKey() throws InvalidKeyStoreException {
		try {
			KeyStore keystore = getKeyStore();
			String alias = getKeyStoreAlias();
			char[] password = getKeyStorePassword();
			PublicKey publicKey = SecureClient.getPublicKey(keystore, alias, password);

			return publicKey;
		} catch (Exception e) {
			throw new InvalidKeyStoreException();
		}
	}

	protected PrivateKey getPrivateKey() throws InvalidKeyStoreException {
		try {
			KeyStore keystore = getKeyStore();
			String alias = getKeyStoreAlias();
			char[] password = getKeyStorePassword();
			PrivateKey privateKey = SecureClient.getPrivateKey(keystore, alias, password);

			return privateKey;
		} catch (Exception e) {
			throw new InvalidKeyStoreException();
		}
	}
	

	protected KeyStore getKeyStore() {
		return _ks;
	}
	
	
	protected pm.ws.Key getPublicKeyToSend() throws InvalidKeyStoreException{
		pm.ws.Key k = new pm.ws.Key();
		k.setKey(ObjectUtil.writeObjectBytes(getPublicKey()));
		return k;
	}
}
