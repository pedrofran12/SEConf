package pm.ws;

import java.util.HashMap;
import java.util.Map;

import javax.jws.WebService;

@WebService(endpointInterface = "pm.ws.PasswordManager")
public class PasswordManagerImpl implements PasswordManager {
		
	//private Map<ByteBuffer, Map<ByteBuffer, byte[]>> password = new HashMap<ByteBuffer, Map<ByteBuffer, byte[]>>();
	private Map<byte[], Map<byte[], byte[]>> password = new HashMap<>();
	
	
	public void register(Key publicKey){
		
	}
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password){
		updatePassword(domain, username, password);
	}
	
	public byte[] get(Key publicKey, byte[] domain, byte[] username){
		/*if(!usersKey.contains(publicKey)) {
			throw new UnauthorizedRequestException(publicKey);
		}*/
		if(!domainUserExists(domain, username)) {
			// throw new UsernameDomainDoesNotExistException(domain, username);
		}
		return password.get(username).get(domain);

	}
	
	private boolean domainUserExists(byte[] domain, byte[] username) {
		// this method might need to be changed do to some possible issues
		// that can only happen during runtime
		return password.containsKey(username) &&
				password.get(username).containsKey(domain);
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
