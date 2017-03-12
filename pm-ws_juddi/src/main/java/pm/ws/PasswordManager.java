package pm.ws;

import javax.jws.WebService;

import pm.exception.InvalidDomainException;
import pm.exception.InvalidKeyException;
import pm.exception.InvalidPasswordException;
import pm.exception.InvalidUsernameException;
import pm.exception.KeyAlreadyExistsException;
import pm.exception.UnknownUsernameDomainException;

@WebService
public interface PasswordManager {
	void register(Key publicKey) throws InvalidKeyException, KeyAlreadyExistsException;

	void put(Key publicKey, byte[] domain, byte[] username, byte[] password)
			throws InvalidKeyException, InvalidDomainException, InvalidUsernameException, InvalidPasswordException;

	byte[] get(Key publicKey, byte[] domain, byte[] username) throws InvalidKeyException, InvalidDomainException,
			InvalidUsernameException, UnknownUsernameDomainException;
}
