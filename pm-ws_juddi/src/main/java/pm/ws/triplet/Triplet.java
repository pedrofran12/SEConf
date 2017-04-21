package pm.ws.triplet;

import java.io.Serializable;
import pm.exception.*;

public class Triplet extends TripletHeader implements Serializable {
	private static final long serialVersionUID = 1L;

	private byte[] password;
	private int wid = -1;
	private int tie = Integer.MIN_VALUE;

	public Triplet(byte[] dmn, byte[] uname, byte[] passwd, int id, int tie)
			throws InvalidPasswordException, InvalidDomainException, InvalidUsernameException {
		super(dmn, uname);
		setPassword(passwd, id, tie);
	}

	public byte[] getPassword() {
		return password;
	}
	
	public int getWriteId(){
		return wid;
	}
	
	public int getTieValue() {
		return tie;
	}

	public void setPassword(byte[] passwd, int wid, int tie) throws InvalidPasswordException {
		if (passwd == null) {
			throw new InvalidPasswordException();
		}
		if(getWriteId() < wid || (getWriteId() == wid && getTieValue() < tie)){
			password = passwd;
			this.wid = wid;
			this.tie = tie;
		}
	}

	public Triplet duplicate(){
		try{
			return new Triplet(getDomain(), getUsername(), getPassword(), getWriteId(), getTieValue());
		}
		catch(Exception e){
			return null;
		}
	}
}
