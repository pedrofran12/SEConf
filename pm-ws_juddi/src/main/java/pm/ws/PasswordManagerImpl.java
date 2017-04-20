package pm.ws;

import java.io.Serializable;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.Resource;
import javax.jws.HandlerChain;
import javax.jws.WebService;
import javax.xml.ws.WebServiceContext;
import javax.xml.ws.handler.MessageContext;

import pm.exception.*;
import pm.handler.ServerHandler;
import pm.ws.triplet.Triplet;
import pm.ws.triplet.TripletStore;
import utilities.ObjectUtil;

import org.apache.commons.net.util.Base64;
import org.apache.log4j.FileAppender;
import org.apache.log4j.Logger;


@WebService(endpointInterface = "pm.ws.PasswordManager")
@HandlerChain(file = "/handler-chain.xml")
public class PasswordManagerImpl implements PasswordManager, Serializable {
	private static final long serialVersionUID = 1L;
	private static final String SAVE_STATE_NAME = "./PasswordManager%d.serial";

	private transient Logger log;
	private int port;
	private final Map<java.security.Key, TripletStore> password;
	
	@Resource
	private transient WebServiceContext webServiceContext;
	
	private PasswordManagerImpl(int port) {
		password = new HashMap<>();
		this.port = port;
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

			MessageContext messageContext = webServiceContext.getMessageContext();
			int wid = (int) messageContext.get(ServerHandler.WRITE_IDENTIFIER_RESPONSE_PROPERTY);
			System.out.printf("PUT() got token '%s' from response context%n", wid);
			
			ts.put(domain, username, password, wid);
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
			TripletStore ts = getTripletStore(key);
			Triplet t = ts.get(domain, username);
			
			int wid = t.getWriteId();
			System.out.printf("GET() put token '%d' on request context%n", wid);
			MessageContext messageContext = webServiceContext.getMessageContext();
			messageContext.put(ServerHandler.WRITE_IDENTIFIER_RESPONSE_PROPERTY, wid);

			byte[] result = t.getPassword();
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
		String fileName = String.format(SAVE_STATE_NAME, port);
		boolean saved = ObjectUtil.writeObjectFile(fileName, this);
		//boolean saved = true;
		if (saved) {
			System.out.println(">>> Saved state");
		} else {
			System.out.println(">>> Failed to save state");
		}
	}

	public static PasswordManager getInstance(int port) {
		String fileName = String.format(SAVE_STATE_NAME, port);
		PasswordManagerImpl pm = ObjectUtil.readObjectFile(fileName, PasswordManagerImpl.class);
		if (pm != null) {
			System.out.println(">>> Loaded state");
		} else {
			pm = new PasswordManagerImpl(port);
			System.out.println(">>> Created");
		}
		pm.setPort(""+port);
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
		String toPrint = logToString(methodName, key, args);
		String resultString = Base64.encodeBase64String(result);
		log(toPrint + " -> " + resultString);
	}
	
	private void log(String methodName, java.security.Key key, byte[]... args){
		String toPrint = logToString(methodName, key, args);
		log(toPrint);
	}

	private void log(String methodName, Exception e, java.security.Key key, byte[]... args){
		String toPrint = logToString(methodName, key, args) + " -> " + e.getClass().getSimpleName();
		log(toPrint);
	}
	
	private void log(String toPrint){
		log.info(new SimpleDateFormat("dd-MM-yyyy HH:mm:ss").format(new Date()) + " : " + toPrint);
	}

	private String logToString(String methodName, java.security.Key key, byte[]... args){
		String logPrint = methodName + "(" + Base64.encodeBase64String(key.getEncoded());

		for(byte[] b : args)
			logPrint += ", " + Base64.encodeBase64String(b);
		logPrint += ")";
		return  logPrint;
	}

}
