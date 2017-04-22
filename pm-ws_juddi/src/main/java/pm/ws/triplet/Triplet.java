package pm.ws.triplet;

import java.io.Serializable;
import pm.exception.*;

public class Triplet extends TripletHeader implements Serializable {
	private static final long serialVersionUID = 1L;

	private byte[] password;
	private int wid = -1;
	private int tie = -1;
	private String widSignature;

	public Triplet(byte[] dmn, byte[] uname, byte[] passwd, int id, int tie, String signature)
			throws InvalidPasswordException, InvalidDomainException, InvalidUsernameException {
		super(dmn, uname);
		setPassword(passwd, id, tie, signature);
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

	public String getWidSignature() {
		return widSignature;
	}

	public void setPassword(byte[] passwd, int wid, int tie, String signature) throws InvalidPasswordException {
		if (passwd == null) {
			throw new InvalidPasswordException();
		}
		if(getWriteId() < wid || (getWriteId() == wid && getTieValue() < tie)){
			password = passwd;
			this.wid = wid;
			this.tie = tie;
			widSignature = signature;
		}
	}

	public Triplet duplicate(){
		try{
			return new Triplet(getDomain(), getUsername(), getPassword(),
					getWriteId(), getTieValue(), getWidSignature());
		}
		catch(Exception e){
			return null;
		}
	}
}
