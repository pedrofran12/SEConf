package pm.ws;

import javax.jws.WebService;

import pm.exception.InvalidKeyException;
import pm.exception.PasswordAlreadyExistsException;
import pm.exception.PasswordManagerException;
import pm.exception.UnauthorizedRequestException;

@WebService
public interface PasswordManager {
	void register(Key publicKey) throws PasswordAlreadyExistsException;
	void put(Key publicKey, byte[] domain, byte[] username, byte[] password) throws PasswordManagerException;
	byte[] get(Key publicKey, byte[] domain, byte[] username) throws PasswordManagerException;
}
