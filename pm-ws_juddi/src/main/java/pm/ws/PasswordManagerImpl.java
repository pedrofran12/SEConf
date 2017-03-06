package pm.ws;

import java.io.Serializable;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;

import javax.jws.HandlerChain;
import javax.jws.WebService;

import pm.exception.*;
import pm.ws.triplet.TripletStore;
import utilities.ObjectUtil;

@WebService(endpointInterface = "pm.ws.PasswordManager")
@HandlerChain(file = "/handler-chain.xml")
public class PasswordManagerImpl implements PasswordManager, Serializable {
	private static final long serialVersionUID = 1L;
	private static final String SAVE_STATE_NAME = "./PasswordManager.serial";

	private final Map<java.security.Key, TripletStore> password;
	private final Lock saveStateLock;

	private PasswordManagerImpl() {
		password = new HashMap<>();
		saveStateLock = new ReentrantLock(true);
	}

	public void register(Key publicKey) throws PasswordManagerException {
		java.security.Key key = keyToKey(publicKey);
		if (password.containsKey(key)) {
			throw new KeyAlreadyExistsException();
		}
		password.put(key, new TripletStore());
		daemonSaveState();
	}

	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws PasswordManagerException {
		java.security.Key key = keyToKey(publicKey);
		TripletStore ts = getTripletStore(key);
		ts.put(domain, username, password);
		daemonSaveState();
	}

	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws PasswordManagerException {
		java.security.Key key = keyToKey(publicKey);
		if (!password.containsKey(key)) {
			throw new InvalidKeyException();
		}
		return password.get(key).get(domain, username);
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
		new Runnable() {
			@Override
			public void run() {
				saveState();
			}
		}.run();
	}

	private void saveState() {
		saveStateLock.lock();
		boolean saved = ObjectUtil.writeObjectFile(SAVE_STATE_NAME, this);
		if (saved) {
			System.out.println(">>> Saved state");
		} else {
			System.out.println(">>> Failed to save state");
		}
		saveStateLock.unlock();
	}

	public static PasswordManager getInstance() {
		PasswordManager pm = ObjectUtil.readObjectFile(SAVE_STATE_NAME, PasswordManagerImpl.class);
		if (pm != null) {
			System.out.println(">>> Loaded state");
		} else {
			System.out.println(">>> Created");
			pm = new PasswordManagerImpl();
		}
		return pm;
	}
}
