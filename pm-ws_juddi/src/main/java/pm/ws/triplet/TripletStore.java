package pm.ws.triplet;

import java.util.ArrayList;
import java.util.List;

public class TripletStore {
	private final List<Triplet> store;
	
	public TripletStore() {
		store = new ArrayList<>();
	}
	
	public void put(byte[] domain, byte[] username, byte[] password) {
		Triplet t = getTriplet(domain, username);
		if (t == null) {
			store.add(new Triplet(domain, username, password));
		} else {
			t.setPassword(password);
		}
	}
	
	public byte[] get(byte[] domain, byte[] username) {
		Triplet t = getTriplet(domain, username);
		if (t == null) {
			// throw new UnknowUsernameDomainException();
		}
		return t.getPassword();
	}
	
	private Triplet getTriplet(byte[] domain, byte[] username) {
		return getTriplet(new TripletHeader(domain, username));
	}
	
	private Triplet getTriplet(TripletHeader th) {
		if (store.contains(th)) {
			return store.get(store.indexOf(th));
		}
		return null;
	}
}
