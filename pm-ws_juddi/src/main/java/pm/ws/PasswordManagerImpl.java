package pm.ws;

import java.util.HashMap;
import java.util.Map;

import javax.jws.WebService;

import pm.exception.InvalidKeyException;
import pm.ws.triplet.TripletStore;

@WebService(endpointInterface = "pm.ws.PasswordManager")
public class PasswordManagerImpl implements PasswordManager {
		
	private Map<Key, TripletStore> password = new HashMap<>();
	
	
	public void register(Key publicKey){
		/*// VERSAO PARA NÃO MONGOLOIDES
		if (!password.containsKey(publicKey)) {
			password.put(publicKey, new TripletStore());
		}
		*/
		// VERSÃO PARA MONGOLOIDES
		if (password.containsKey(publicKey)) {
			// throw new VaiTeTratarOhMongoloideException();
		}
		password.put(publicKey, new TripletStore());
	}
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws InvalidKeyException {
		TripletStore ts = getTripletStore(publicKey);
		ts.put(domain, username, password);
	}
	
	
	public byte[] get(Key publicKey, byte[] domain, byte[] username){
		if(!password.containsKey(publicKey)) {
			// throw new UnauthorizedRequestException(publicKey);
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
