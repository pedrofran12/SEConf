package pm.ws.triplet;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

public class TripletStore {
	private final List<Triplet> store;
	private final Lock wLock;
	private final Lock rLock;
	
	public TripletStore() {
		store = new ArrayList<>();
		ReentrantReadWriteLock rrwl = new ReentrantReadWriteLock(true);
		wLock = rrwl.writeLock();
		rLock = rrwl.readLock();
	}
	
	public void put(byte[] domain, byte[] username, byte[] password) {
		wLock.lock();
		Triplet t = getTriplet(domain, username);
		if (t == null) {
			store.add(new Triplet(domain, username, password));
		} else {
			t.setPassword(password);
		}
		wLock.unlock();
	}
	
	public byte[] get(byte[] domain, byte[] username) {
		rLock.lock();
		byte[] passwd = null;
		Triplet t = getTriplet(domain, username);
		if (t != null) {
			passwd = t.getPassword();
		}
		rLock.unlock();
		if (passwd != null) {
			// throw new UnknowUsernameDomainException();
		}
		return passwd;
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
