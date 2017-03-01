package pm.ws.triplet;

import java.io.Serializable;

public class Triplet extends TripletHeader implements Serializable {
	private static final long serialVersionUID = 1L;
	
	private byte[] password;

	public Triplet(byte[] dmn, byte[] uname, byte[] passwd) {
		super(dmn, uname);
		setPassword(passwd);
	}
	
	public byte[] getPassword() {
		return password;
	}
	
	public void setPassword(byte[] passwd) {
		if (passwd == null) {
			//throw new InvalidPasswordException();
		}
		password = passwd;
	}
}
