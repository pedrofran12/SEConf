package pm;

import javax.jws.WebMethod;
import javax.jws.WebService;

@WebService(endpointInterface = "pm.PasswordManager")
public class PasswordManagerImpl implements PasswordManager, java.io.Serializable{
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;

	public PasswordManagerImpl(){
		
	}
	
	@WebMethod(exclude = true)
	public void register(Key publicKey){
		
	}
	
	@WebMethod(exclude = true)
	public void put(Key publicKey, byte[] domain, byte[] username, byte[] password){
		
	}
	
	@WebMethod(exclude = true)
	public byte[] get(Key publicKey, byte[] domain, byte[] username){
		return null;
	}

}
