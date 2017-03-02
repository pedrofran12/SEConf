package pm.ws;

import java.util.HashMap;
import java.util.Map;

import javax.jws.WebService;

import pm.exception.*;
import pm.ws.triplet.TripletStore;

@WebService(endpointInterface = "pm.ws.PasswordManager")
public class PasswordManagerImpl implements PasswordManager {
		
	private Map<Key, TripletStore> password = new HashMap<>();
	
	
	public void register(Key publicKey) throws PasswordAlreadyExistsException{
		if (password.containsKey(publicKey)) {
			throw new PasswordAlreadyExistsException();
		}
		password.put(publicKey, new TripletStore());
	}
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws PasswordManagerException {
		TripletStore ts = getTripletStore(publicKey);
		ts.put(domain, username, password);
	}
	
	
	public byte[] get(Key publicKey, byte[] domain, byte[] username) throws PasswordManagerException{
		if(!password.containsKey(publicKey)) {
			throw new UnauthorizedRequestException();
		}
		return password.get(publicKey).get(domain, username);
	}
	
	
	private TripletStore getTripletStore(Key k) throws InvalidKeyException{
		TripletStore ts = password.get(k);
		if(ts==null)
			throw new InvalidKeyException();
		return ts;
	}
	
}
