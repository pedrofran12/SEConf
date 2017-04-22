package pm.ws.triplet;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;
import pm.exception.*;

public class TripletStore implements Serializable {
	private static final long serialVersionUID = 1L;

	private final List<Triplet> store;
	private final Lock wLock;
	private final Lock rLock;

	public TripletStore() {
		store = new ArrayList<>();
		ReentrantReadWriteLock rrwl = new ReentrantReadWriteLock(true);
		wLock = rrwl.writeLock();
		rLock = rrwl.readLock();
	}

	public void put(byte[] domain, byte[] username, byte[] password, int wid, int tie, String signature)
			throws InvalidDomainException, InvalidUsernameException, InvalidPasswordException {
		wLock.lock();
		try {
			Triplet t = getTriplet(domain, username);
			if (t == null) {
				store.add(new Triplet(domain, username, password, wid, tie, signature));
			} else {
				t.setPassword(password, wid, tie, signature);
			}
		} catch (InvalidDomainException | InvalidUsernameException | InvalidPasswordException e) {
			throw e;
		} finally {
			wLock.unlock();
		}
	}

	public Triplet get(byte[] domain, byte[] username)
			throws InvalidDomainException, InvalidUsernameException, UnknownUsernameDomainException {
		rLock.lock();
		try {
			Triplet t = getTriplet(domain, username);
			if (t == null) {
				throw new UnknownUsernameDomainException();
			}
			return t.duplicate();
		} catch (InvalidDomainException | InvalidUsernameException | UnknownUsernameDomainException e) {
			throw e;
		} finally {
			rLock.unlock();
		}
	}

	private Triplet getTriplet(byte[] domain, byte[] username) throws InvalidDomainException, InvalidUsernameException {
		return getTriplet(new TripletHeader(domain, username));
	}

	private Triplet getTriplet(TripletHeader th) {
		// Looks for Triplet header similar to th
		for (Triplet t : store) {
			if (t.equals(th)) {
				return t;
			}
		}
		return null;
	}
}
