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

    public void put(byte[] domain, byte[] username, byte[] password) throws PasswordManagerException {

        PasswordManagerException possibleException = null;
        wLock.lock();

        try {
            Triplet t = getTriplet(domain, username);
            if (t == null) {
                store.add(new Triplet(domain, username, password));
            } else {
                t.setPassword(password);
            }

        } catch (PasswordManagerException e) {
            possibleException = e;
        
        } finally {
            wLock.unlock();
        }

        if (possibleException != null) {
            throw possibleException;
        }
    }

    public byte[] get(byte[] domain, byte[] username) throws PasswordManagerException{
        PasswordManagerException possibleException = null;
        
        rLock.lock();
        byte[] passwd = null;
        try {
        
            Triplet t = getTriplet(domain, username);
            if (t != null) {
                passwd = t.getPassword();
            }
            
        } catch (PasswordManagerException e) {
            possibleException = e;
            
        } finally {
            rLock.unlock();
        }
        
        if(possibleException != null){
            throw possibleException;
        }
        
        if (passwd == null) {
            throw new UnknownUsernameDomainException();
        }
        return passwd;
    }

    private Triplet getTriplet(byte[] domain, byte[] username) throws InvalidDomainException, InvalidUsernameException {
        return getTriplet(new TripletHeader(domain, username));
    }

    private Triplet getTriplet(TripletHeader th) {
        //Looks for Triplet header similar to th
        for (Triplet t : store) {
            if (t.equals(th)) {
                return t;
            }
        }
        return null;
    }
}
