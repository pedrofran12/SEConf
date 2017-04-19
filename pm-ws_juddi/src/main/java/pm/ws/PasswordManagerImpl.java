package pm.ws;

import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.jws.HandlerChain;
import javax.jws.WebService;

import pm.exception.*;
import pm.handler.ServerHandler;
import pm.ws.triplet.TripletStore;
import utilities.ObjectUtil;

import org.apache.commons.net.util.Base64;
import org.apache.log4j.FileAppender;
import org.apache.log4j.Logger;


@WebService(endpointInterface = "pm.ws.PasswordManager")
@HandlerChain(file = "/handler-chain.xml")
public class PasswordManagerImpl implements PasswordManager, Serializable {
	private static final long serialVersionUID = 1L;
	private static final String SAVE_STATE_NAME = "./PasswordManager.serial";
	private transient Logger log;

	private final Map<java.security.Key, TripletStore> password;
	
	private PasswordManagerImpl() {
		password = new HashMap<>();
	}

	public void register(Key publicKey) throws InvalidKeyException, KeyAlreadyExistsException {
		java.security.Key key = keyToKey(publicKey);
		try {
			if (password.containsKey(key)) {
				throw new KeyAlreadyExistsException();
			}
			password.put(key, new TripletStore());
			daemonSaveState();
			log("register", key);

		}
		catch (Exception e) {
			log("register", e, key);
			throw e;
		}

	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password)
			throws InvalidKeyException, InvalidDomainException, InvalidUsernameException, InvalidPasswordException {
		java.security.Key key = keyToKey(publicKey);
		try{
			TripletStore ts = getTripletStore(key);
			ts.put(domain, username, password);
			daemonSaveState();
			log("put", key, domain, username, password);	
		}
		catch (Exception e) {
			log("put", e, key, domain, username, password);
			throw e;
		}
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws InvalidKeyException, InvalidDomainException,
			InvalidUsernameException, UnknownUsernameDomainException {
		java.security.Key key = keyToKey(publicKey);
		try{
			if (!password.containsKey(key)) {
				throw new InvalidKeyException();
			}
			byte[] result = password.get(key).get(domain, username);
			log("get", result, key, domain, username, result);
			return result;
		}
		catch (Exception e) {
			log("get", e, key, domain, username);
			throw e;
		}
	}

	private TripletStore getTripletStore(java.security.Key k) throws InvalidKeyException {
		TripletStore ts = password.get(k);
		if (ts == null)
			throw new InvalidKeyException();
		return ts;
	}

	private java.security.Key keyToKey(Key k) throws InvalidKeyException {
		return ObjectUtil.readObjectBytes(k.getKey(), java.security.Key.class);
	}

	private void daemonSaveState() {
		new Thread(new Runnable() {
			@Override
			public void run() {
				saveState();
			}
		}).start();
	}

	private synchronized void saveState() {
		boolean saved = ObjectUtil.writeObjectFile(SAVE_STATE_NAME, this);
		if (saved) {
			System.out.println(">>> Saved state");
		} else {
			System.out.println(">>> Failed to save state");
		}
	}

	public static PasswordManager getInstance() {
		PasswordManagerImpl pm = ObjectUtil.readObjectFile(SAVE_STATE_NAME, PasswordManagerImpl.class);
		if (pm != null) {
			System.out.println(">>> Loaded state");
		} else {
			pm = new PasswordManagerImpl();
			System.out.println(">>> Created");
		}
		pm.setPort("8080");
		return pm;
	}
	
	private void setPort(String port) {
		//Set logger filename
		System.setProperty("file.port", port);
		log = Logger.getLogger(PasswordManagerImpl.class.getName() + port);
		//set privatekey
		ServerHandler.setPrivateKey(port);
	}
	
	private void log(String methodName, byte[] result, java.security.Key key, byte[]... args){
		String argsString = "(" + Base64.encodeBase64String(key.getEncoded());

		for(byte[] b : args)
			argsString += ", " + Base64.encodeBase64String(b);
		argsString += ")";
		String resultString = Base64.encodeBase64String(result);
		log.info(new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Date()) + " : " + methodName + argsString + " -> " + resultString);
	}
	
	private void log(String methodName, java.security.Key key, byte[]... args){
		String argsString = "(" + Base64.encodeBase64String(key.getEncoded());

		for(byte[] b : args)
			argsString += ", " + Base64.encodeBase64String(b);
		argsString += ")";
		log.info(new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Date()) + " : " + methodName + argsString);
	}

	private void log(String methodName, Exception e, java.security.Key key, byte[]... args){
		String argsString = "(" + Base64.encodeBase64String(key.getEncoded());

		for(byte[] b : args)
			argsString += ", " + Base64.encodeBase64String(b);
		argsString += ")";
		log.warn(new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Date()) + " : " + methodName + argsString + " -> " + e.getClass().getSimpleName());
	}

}
