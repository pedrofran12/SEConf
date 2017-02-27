package pm;

import java.util.List;

import javax.jws.WebMethod;
import javax.jws.WebService;

import pm.exception.InvalidKeyException;
import pm.exception.KeyAlreadyExistsException;

@WebService(endpointInterface = "pm.PasswordManager")
public class PasswordManagerImpl implements PasswordManager {
    
    private List<Key> usersKey; //stores usersKeys
		
	public void register(Key publicKey) throws KeyAlreadyExistsException, InvalidKeyException{
	    //OnlyKey
	    if(publicKey == null)
	        throw new InvalidKeyException();
	    else if(checkKey(publicKey))
	        throw new KeyAlreadyExistsException();
	    else{
	        usersKey.add(publicKey);
	    }
	    
	    //KeyPair
	}
	
	private boolean checkKey(Key k){
	    return usersKey.contains(k);
	}
	
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password){

	}
	
	public byte[] get(Key publicKey, byte[] domain, byte[] username){
		return null;
	}

}
