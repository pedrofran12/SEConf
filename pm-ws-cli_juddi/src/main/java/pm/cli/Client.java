package pm.cli;

import java.security.cert.Certificate;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.util.*;
import javax.xml.ws.*;
import static javax.xml.ws.BindingProvider.ENDPOINT_ADDRESS_PROPERTY;

import pt.ulisboa.tecnico.seconf.ws.uddi.UDDINaming;

import pm.ws.*;// classes generated from WSDL

public class Client {

	private PasswordManager pm;
	private Scanner keyboardSc;
	private KeyStore _ks;
	private String alias;
	private char[] password;

	public static void main(String[] args) throws Exception {
		// Check arguments
		if (args.length < 2) {
			System.err.println("Argument(s) missing!");
			System.err.printf("Usage: java %s uddiURL name%n", Client.class.getName());
			return;
		}

		String uddiURL = args[0];
		String name = args[1];

		System.out.printf("Contacting UDDI at %s%n", uddiURL);
		UDDINaming uddiNaming = new UDDINaming(uddiURL);

		System.out.printf("Looking for '%s'%n", name);
		String endpointAddress = uddiNaming.lookup(name);

		if (endpointAddress == null) {
			System.out.println("Not found!");
			return;
		} else {
			System.out.printf("Found %s%n", endpointAddress);
		}

		System.out.println("Creating stub ...");
		PasswordManagerImplService service = new PasswordManagerImplService();
		PasswordManager port = service.getPasswordManagerImplPort();

		System.out.println("Setting endpoint address ...");
		BindingProvider bindingProvider = (BindingProvider) port;
		Map<String, Object> requestContext = bindingProvider.getRequestContext();
		requestContext.put(ENDPOINT_ADDRESS_PROPERTY, endpointAddress);

		Client c = new Client(port);

		// ****** obter keystore ******
		String alias = "client";
		char[] password = "benfica".toCharArray();
		KeyStore ks = KeyStore.getInstance("JKS");
		InputStream readStream = new FileInputStream("src/main/resources/KeyStore.jks");
		ks.load(readStream, password);
		java.security.Key key = ks.getKey(alias, password);
		readStream.close();
		// ****************************
		c.init(ks, alias, password);

		c.doCode();
	}

	private void doCode() {
		// Here is the code for your test//
		// just do: pm.something();
	}

	public Client(PasswordManager port) {
		this.pm = port;
		keyboardSc = new Scanner(System.in);
	}

	public void init(KeyStore ks, String alias, char[] password) {
		setKeyStore(ks);
		setKeyStoreAlias(alias);
		setKeyStorePassword(password);
	}

	public void register_user() throws Exception {
		Key k = getPublicKey();
		//pm.register(k);
	}

	public void save_password(byte[] domain, byte[] username, byte[] password){
    	Key key = getPublicKey();
    	try {
    		_pm.put(key, domain, username, password);
    	} catch (PasswordManagerException pme) {
    		pme.printStackTrace();
    	}
    }

	public byte[] retrieve_password(byte[] domain, byte[] username) {

		return null;
	}

	private KeyStore getKeyStore() {
		return _ks;
	}

	private Key getPublicKey() throws Exception {
		KeyStore keystore = getKeyStore();
		String alias = getKeyStoreAlias();
		Key key = keystore.getKey(alias, getKeyStorePassword());
		if (key instanceof PrivateKey) {
			// Get certificate of public key
			Certificate cert = keystore.getCertificate(alias);

			// Get public key
			PublicKey publicKey = cert.getPublicKey();
			return new pm.ws.Key(publicKey);
		}

		throw new Exception("key");
	}

	private void setKeyStore(KeyStore k) {
		_ks = k;
	}

	private void setKeyStoreAlias(String alias) {
		this.alias = alias;
	}

	private void setKeyStorePassword(char[] password) {
		this.password = password;
	}

	private String getKeyStoreAlias() {
		return alias;
	}

	private char[] getKeyStorePassword() {
		return password;
	}
}
