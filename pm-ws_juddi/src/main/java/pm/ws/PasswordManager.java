package pm.ws;

import javax.jws.WebService;

import pm.exception.InvalidKeyException;

@WebService
public interface PasswordManager {
	void register(Key publicKey);
	void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws InvalidKeyException;
	byte[] get(Key publicKey, byte[] domain, byte[] username);
}
