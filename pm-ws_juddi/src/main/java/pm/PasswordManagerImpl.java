package pm;

import java.security.Key;

import javax.jws.WebService;

@WebService(endpointInterface = "pm.PasswordManager")
public class PasswordManagerImpl implements PasswordManager {
	
	public void register(Key publicKey){
		
	}
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password){
		
	}
	public byte[] get(Key publicKey, byte[] domain, byte[] username){
		return null;
	}

}
