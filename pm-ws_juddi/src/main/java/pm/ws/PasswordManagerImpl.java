package pm.ws;

import java.io.Serializable;
import java.security.PublicKey;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.FileHandler;
import java.util.logging.Logger;
import java.util.logging.SimpleFormatter;

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


@WebService(endpointInterface = "pm.ws.PasswordManager")
@HandlerChain(file = "/handler-chain.xml")
public class PasswordManagerImpl implements PasswordManager, Serializable {
	private static final long serialVersionUID = 1L;
	private static final String SAVE_STATE_NAME = "./PasswordManager%d.serial";
	private static final String WID_SEPARATOR = ":";
	private static final boolean AUTO_REGISTER = true;

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
		PublicKey key = keyToKey(publicKey);
		try {
			if (password.containsKey(key)) {
				throw new KeyAlreadyExistsException();
			}
			password.put(key, new TripletStore(key));
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
		PublicKey key = keyToKey(publicKey);
		try{
			TripletStore ts = getTripletStore(key);

			MessageContext messageContext = webServiceContext.getMessageContext();
			String widForm = (String) messageContext.get(ServerHandler.WRITE_IDENTIFIER_RESPONSE_PROPERTY);
			String[] splited = widForm.split(WID_SEPARATOR, 3);
            int wid = Integer.parseInt(splited[0]);
            int tie = Integer.parseInt(splited[1]);
            String widSignature = splited[2];
			System.out.printf("PUT() got token '%d' from response context%n", wid);
			
			ts.put(domain, username, password, wid, tie, widSignature);
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
		PublicKey key = keyToKey(publicKey);
		try{
			TripletStore ts = getTripletStore(key);
			Triplet t = ts.get(domain, username);
			
			int wid = t.getWriteId();
			int tie = t.getTieValue();
			String widForm = wid + WID_SEPARATOR + tie + WID_SEPARATOR + t.getWidSignature();
			System.out.printf("GET() put token '%d' on request context%n", wid);
			MessageContext messageContext = webServiceContext.getMessageContext();
			messageContext.put(ServerHandler.WRITE_IDENTIFIER_RESPONSE_PROPERTY, widForm);

			byte[] result = t.getPassword();
			log("get", result, key, domain, username, result);
			return result;
		}
		catch (Exception e) {
			log("get", e, key, domain, username);
			throw e;
		}
	}

	private TripletStore getTripletStore(PublicKey k) throws InvalidKeyException {
		TripletStore ts = password.get(k);
		if (ts == null) {
			if (!AUTO_REGISTER)
				throw new InvalidKeyException();
			ts = new TripletStore(k);
			password.put(k, ts);
		}
		return ts;
	}

	private PublicKey keyToKey(Key k) throws InvalidKeyException {
		return ObjectUtil.readObjectBytes(k.getKey(), java.security.PublicKey.class);
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
		log = Logger.getLogger(PasswordManagerImpl.class.getSimpleName() + port);
		log.setUseParentHandlers(false); // don't write to console
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
		try {
			FileHandler fh = new FileHandler(PasswordManagerImpl.class.getSimpleName() + port + ".out", true);
			SimpleFormatter formatter = new SimpleFormatter();  
	        fh.setFormatter(formatter);
	        log.addHandler(fh);
			log.info(toPrint);
			fh.flush();
			fh.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private String logToString(String methodName, java.security.Key key, byte[]... args){
		String logPrint = methodName + "(" + Base64.encodeBase64String(key.getEncoded());

		for(byte[] b : args)
			logPrint += ", " + Base64.encodeBase64String(b);
		logPrint += ")";
		return  logPrint;
	}

}
