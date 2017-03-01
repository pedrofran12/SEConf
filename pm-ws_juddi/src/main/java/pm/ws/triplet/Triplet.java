package pm.ws.triplet;

public class Triplet extends TripletHeader {
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
