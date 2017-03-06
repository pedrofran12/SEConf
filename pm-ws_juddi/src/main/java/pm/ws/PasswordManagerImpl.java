package pm.ws;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
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
	private static final String SAVE_STATE_NAME = "PasswordManager.serial";

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
		try {
			FileOutputStream fos = new FileOutputStream(SAVE_STATE_NAME);
			ObjectOutputStream oos = new ObjectOutputStream(fos);
			oos.writeObject(this);
			oos.flush();
			oos.close();
			fos.close();
			System.out.println(">>> Saved state");
		} catch (Exception e) {
			System.out.println(">>> Failed to save state");
		}
		saveStateLock.unlock();
	}
	
	public static PasswordManager getInstance() {
		try {
			FileInputStream fis = new FileInputStream(SAVE_STATE_NAME);
			ObjectInputStream ois = new ObjectInputStream(fis);
			PasswordManager pm = (PasswordManagerImpl) ois.readObject();
			ois.close();
			fis.close();
			System.out.println(">>> Loaded state");
			return pm;
		} catch (Exception e) {
			System.out.println(">>> Created");
			return new PasswordManagerImpl();
		}
	}
}
