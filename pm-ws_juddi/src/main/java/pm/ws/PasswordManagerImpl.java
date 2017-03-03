package pm.ws;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.util.HashMap;
import java.util.Map;

import javax.jws.HandlerChain;
import javax.jws.WebService;

import pm.exception.*;
import pm.ws.triplet.TripletStore;

@WebService(endpointInterface = "pm.ws.PasswordManager")
@HandlerChain(file="/handler-chain.xml")
public class PasswordManagerImpl implements PasswordManager {
		
	private Map<java.security.Key, TripletStore> password = new HashMap<>();
	
	
	public void register(Key publicKey) throws PasswordManagerException {
		if (password.containsKey(publicKey)) {
			throw new KeyAlreadyExistsException();
		}
		password.put(keyToKey(publicKey), new TripletStore());
	}
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws PasswordManagerException {
		TripletStore ts = getTripletStore(publicKey);
		ts.put(domain, username, password);
	}
	
	
	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws PasswordManagerException{
		if(!password.containsKey(keyToKey(publicKey))) {
			throw new InvalidKeyException();
		}
		return password.get(keyToKey(publicKey)).get(domain, username);
	}
	
	
	private TripletStore getTripletStore(Key k) throws InvalidKeyException{
		TripletStore ts = password.get(keyToKey(k));
		if(ts==null)
			throw new InvalidKeyException();
		return ts;
	}
	
	
	private java.security.Key keyToKey(Key k) throws InvalidKeyException {
		try{
			ByteArrayInputStream bis = new ByteArrayInputStream(k.getKey());
			ObjectInput in = new ObjectInputStream(bis);
			in.close();
			bis.close();
			return (java.security.Key) in.readObject();
		}
		catch(Exception e){
			throw new InvalidKeyException();
		}
	}
}
