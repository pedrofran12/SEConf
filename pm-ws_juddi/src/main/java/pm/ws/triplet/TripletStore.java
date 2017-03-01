package pm.ws.triplet;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

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
		for (Triplet t : store) {
			if (t.equals(th)) {
				return t;
			}
		}
		return null;
	}
	
	public static void main(String... args) {
		TripletStore ts = new TripletStore();
		byte[] dom1 = "facebosta".getBytes();
		byte[] use1 = "manel".getBytes();
		byte[] dom2 = "fuckbook".getBytes();
		byte[] use2 = "pai_natal".getBytes();
		byte[] dom3 = "escola".getBytes();
		byte[] use3 = "aluno".getBytes();
		byte[] dom4 = "foda-se".getBytes();
		byte[] use4 = "caralho".getBytes();
		ts.put(dom1, use1, "123passwd321".getBytes());
		byte[] pass = ts.get(dom1, use1);
		System.out.println(new String(pass));
		ts.put(dom1, use1, "queres_cona".getBytes());
		pass = ts.get(dom1, use1);
		System.out.println(new String(pass));
		ts.put(dom2, use2, "chupa-aqui".getBytes());
		pass = ts.get(dom2, use2);
		System.out.println(new String(pass));
		ts.put(dom3, use3, "mama_ali".getBytes());
		pass = ts.get(dom3, use3);
		System.out.println(new String(pass));
		ts.put(dom4, use4, "e_ir_para_o_caralho".getBytes());
		pass = ts.get(dom4, use4);
		System.out.println(new String(pass));
	
		
		ts.put(dom4, use4, "e_ir_para_o_caralho12".getBytes());
		pass = ts.get(dom4, use4);
		System.out.println(new String(pass));

	
		ts.put(dom4, use4, "e_ir_para_o_caral".getBytes());
		pass = ts.get(dom4, use4);
		System.out.println(new String(pass));

	}
}
