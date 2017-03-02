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
        PasswordManagerException possibleExeption = null;
        
        rLock.lock();
        byte[] passwd = null;
        try {
        
            Triplet t = getTriplet(domain, username);
            if (t != null) {
                passwd = t.getPassword();
            }
            
        } catch (PasswordManagerException e) {
            possibleExeption = e;
            
        } finally {
            rLock.unlock();
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
        // procura o Triplet equivalente ao TripletHeader th
        for (Triplet t : store) {
            if (t.equals(th)) {
                return t;
            }
        }
        return null;
    }

    /*
     * public static void main(String... args) { TripletStore ts = new
     * TripletStore(); byte[] dom1 = "facebook".getBytes(); byte[] use1 =
     * "manuel".getBytes(); byte[] dom2 = "twitter".getBytes(); byte[] use2 =
     * "afonso".getBytes(); byte[] dom3 = "tecnico".getBytes(); byte[] use3 =
     * "aluno".getBytes(); byte[] dom4 = "instagram".getBytes(); byte[] use4 =
     * "photo".getBytes();
     * 
     * ts.put(dom1, use1, "123passwd321".getBytes()); byte[] pass = ts.get(dom1,
     * use1); System.out.println(new String(pass));
     * 
     * ts.put(dom1, use1, "dwssap123456".getBytes()); pass = ts.get(dom1, use1);
     * System.out.println(new String(pass));
     * 
     * ts.put(dom2, use2, "passarinho".getBytes()); pass = ts.get(dom2, use2);
     * System.out.println(new String(pass));
     * 
     * ts.put(dom3, use3, "hard_coded".getBytes()); pass = ts.get(dom3, use3);
     * System.out.println(new String(pass));
     * 
     * ts.put(dom4, use4, "vou_mudar_a_pass".getBytes()); pass = ts.get(dom4,
     * use4); System.out.println(new String(pass));
     * 
     * ts.put(dom4, use4, "mais_uma_vez".getBytes()); pass = ts.get(dom4, use4);
     * System.out.println(new String(pass));
     * 
     * ts.put(dom4, use4, "ja_esta_tudo_alterado".getBytes()); pass =
     * ts.get(dom4, use4); System.out.println(new String(pass));
     * 
     * }
     */
}
