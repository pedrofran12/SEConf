package pm;

import java.util.HashMap;
import java.util.Map;

import javax.jws.WebMethod;
import javax.jws.WebService;
import java.nio.ByteBuffer;

@WebService(endpointInterface = "pm.PasswordManager")
public class PasswordManagerImpl implements PasswordManager {
		
	//private Map<ByteBuffer, Map<ByteBuffer, byte[]>> password = new HashMap<ByteBuffer, Map<ByteBuffer, byte[]>>();
	private Map<byte[], Map<byte[], byte[]>> password = new HashMap<>();
	
	
	public void register(Key publicKey){
		
	}
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password){
		updatePassword(domain, username, password);
	}
	
	public byte[] get(Key publicKey, byte[] domain, byte[] username){
		return null;
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
