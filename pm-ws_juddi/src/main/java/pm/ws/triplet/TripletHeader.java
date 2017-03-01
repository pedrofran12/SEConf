package pm.ws.triplet;

import java.io.Serializable;
import java.util.Arrays;

public class TripletHeader implements Serializable {
	private static final long serialVersionUID = 1L;
	
	private final byte[] domain;
	private final byte[] username;
	
	
	public TripletHeader(byte[] dmn, byte[] uname) {
		if (dmn == null) {
			// throw new InvalidDomainException();
		}
		if (uname == null) {
			// throw new InvalidUsernameException();
		}
		domain = dmn;
		username = uname;
	}
	
	public byte[] getDomain() {
		return domain;
	}
	
	public byte[] getUsername() {
		return username;
	}
	
	public final boolean equals(TripletHeader th) {
		return Arrays.equals(domain, th.getDomain()) &&
				Arrays.equals(username, th.getUsername());
	}
}
