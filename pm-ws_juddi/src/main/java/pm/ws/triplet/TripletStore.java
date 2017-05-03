package pm.ws.triplet;

import java.io.Serializable;
import java.security.Key;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

import pm.exception.*;
import pm.handler.ServerHandler;
import pm.ws.SecureServer;

public class TripletStore implements Serializable {
	private static final long serialVersionUID = 1L;
	private static final String WID_SEPARATOR = ":";

	
	private final List<Triplet> store;
	private final Lock wLock;
	private final Lock rLock;
	private final PublicKey clientPublicKey;

	public TripletStore(PublicKey k) {
		store = new ArrayList<>();
		ReentrantReadWriteLock rrwl = new ReentrantReadWriteLock(true);
		wLock = rrwl.writeLock();
		rLock = rrwl.readLock();
		clientPublicKey = k;
	}

	public void put(byte[] domain, byte[] username, byte[] password, int wid, int tie, String signature)
			throws InvalidDomainException, InvalidUsernameException, InvalidPasswordException {
		if(!verifySignature(signature, wid, tie, domain, username, password))
			throw new InvalidPasswordException();
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
	private byte[] generateFormWidMac(int wid, int tie, byte[]... values) {
		String toMake = wid + WID_SEPARATOR + tie;
		for (byte[] value : values) {
			toMake += WID_SEPARATOR + Base64.getEncoder().encodeToString(value);
		}
		return toMake.getBytes();
	}
	
	
	private boolean verifySignature(String signatureString, int wid, int tie, byte[]... values) {
		try {
			//byte[] bytesForMac = generateFormWidMac(wid, tie, values);
			//byte[] bytesForSignature = generateFormWidMac(wid, tie, values);
			String toMake = wid + WID_SEPARATOR + tie;
			for (byte[] value : values) {
				toMake += WID_SEPARATOR + Base64.getEncoder().encodeToString(value);
			}
			byte[] bytesForSignature = toMake.getBytes();
			
			//byte[] mac = Base64.getDecoder().decode(macString);
			byte[] signature = Base64.getDecoder().decode(signatureString);
			//return SecureClient.verifyMAC(symmetricKey, mac, bytesForMac);
			return SecureServer.verifySignature(clientPublicKey, signature, bytesForSignature);
		} catch (Exception e) {
			return false;
		}
	}
}
