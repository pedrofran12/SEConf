package pm.ws;

import java.util.HashMap;
import java.util.Map;

import javax.jws.WebService;

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
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password){
		updatePassword(domain, username, password);
	}
	
	public byte[] get(Key publicKey, byte[] domain, byte[] username){
		if(!password.containsKey(publicKey)) {
			// throw new UnauthorizedRequestException(publicKey);
		}
		return password.get(publicKey).get(domain, username);
	}
	
	
	private Map<byte[], byte[]> getUserData(byte[] username){
		Map<byte[], byte[]> userinfo = password.get(username);
		return userinfo;
	}

	
	private void updatePassword(byte[] domain, byte[] username, byte[] password){
		Map<byte[], byte[]> user = getUserData(username);
		if(user==null){
			createUser(username);
			user = getUserData(username);
		}
		
		user.put(domain, password);
	}
	
	private void createUser(byte[] username){
		password.put(username, new HashMap<>());
	}
}
