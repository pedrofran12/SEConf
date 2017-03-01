package pm.ws.triplet;

import java.io.Serializable;
import pm.exception.*;

public class Triplet extends TripletHeader implements Serializable {
	private static final long serialVersionUID = 1L;
	
	private byte[] password;

	public Triplet(byte[] dmn, byte[] uname, byte[] passwd) throws InvalidPasswordException  {
		super(dmn, uname);
		setPassword(passwd);
	}
	
	public byte[] getPassword() {
		return password;
	}
	
	public void setPassword(byte[] passwd) throws InvalidPasswordException {
		if (passwd == null) {
			throw new InvalidPasswordException();
		}
		password = passwd;
	}
}
