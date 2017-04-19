package pm.ws.triplet;

import java.io.Serializable;
import pm.exception.*;

public class Triplet extends TripletHeader implements Serializable {
	private static final long serialVersionUID = 1L;

	private byte[] password;
	private int wid = -1;

	public Triplet(byte[] dmn, byte[] uname, byte[] passwd, int id)
			throws InvalidPasswordException, InvalidDomainException, InvalidUsernameException {
		super(dmn, uname);
		setPassword(passwd, id);
	}

	public byte[] getPassword() {
		return password;
	}
	
	public int getWriteId(){
		return wid;
	}

	public void setPassword(byte[] passwd, int wid) throws InvalidPasswordException {
		if (passwd == null) {
			throw new InvalidPasswordException();
		}
		if(getWriteId() < wid){
			password = passwd;
			this.wid = wid;
		}
	}
	

	public Triplet duplicate(){
		try{
			return new Triplet(getDomain(), getUsername(), getPassword(), getWriteId());
		}
		catch(Exception e){
			return null;
		}
	}
}
