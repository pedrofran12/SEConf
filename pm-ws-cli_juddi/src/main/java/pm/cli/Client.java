package pm.cli;

import static javax.xml.ws.BindingProvider.ENDPOINT_ADDRESS_PROPERTY;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Base64;
import java.util.Map;

import javax.xml.ws.BindingProvider;

// classes generated from WSDL
import pm.ws.PasswordManager;
import pm.ws.PasswordManagerImplService;
import pt.ulisboa.tecnico.seconf.ws.uddi.UDDINaming;

public class Client {
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

		ClientLib c = new ClientLib(port);

		// ****** Get Keystore ******
		String alias = "client";
		char[] password = "benfica".toCharArray();
		KeyStore ks = KeyStore.getInstance("JKS");
		InputStream readStream = new FileInputStream("src/main/resources/KeyStore.jks");
		ks.load(readStream, password);
		readStream.close();
		/*
		String alias = "selfsigned";
		char[] password = "password".toCharArray();
		FileInputStream readStream = new FileInputStream("KeyStore.jks");
		
	    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
	    ks.load(readStream, password);
		*/
		// ****************************
		
		c.init(ks, alias, password);
		c.register_user();
		c.save_password("facebook.com".getBytes(), "pedro".getBytes(), "seconf".getBytes());
		System.out.println("Ciphered Password: "+Base64.getEncoder().encodeToString("facebook.com".getBytes()));
		System.out.println("Password: "+new String(c.retrieve_password("facebook.com".getBytes(), "pedro".getBytes())));
	}
	
	private pm.ws.Key getPrivateKey() throws Exception{
	    //Adapted from javaDOC//
	    
	    //Get PrivateKey!
	    KeyStore.ProtectionParameter protParam =
	            new KeyStore.PasswordProtection(getKeyStorePassword());
	    
	    KeyStore ks = getKeyStore();
	    
	    KeyStore.PrivateKeyEntry pkEntry = (KeyStore.PrivateKeyEntry)
	            ks.getEntry(getKeyStoreAlias(), protParam);
	    
	    PrivateKey privateKey = pkEntry.getPrivateKey();
	    

        // Convert PrivateKey to pm.ws.Key
        pm.ws.Key pk = new pm.ws.Key();
        pk.setKey(Base64.getEncoder().encodeToString(privateKey.getEncoded()));
        pk.setAlgorithm(privateKey.getAlgorithm());
	    
	    return pk;
	}
}
