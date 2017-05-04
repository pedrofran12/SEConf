package pm.cli;

import static javax.xml.ws.BindingProvider.ENDPOINT_ADDRESS_PROPERTY;

import java.util.ArrayList;
import java.util.Map;

import javax.xml.ws.BindingProvider;

// classes generated from WSDL
import pm.ws.PasswordManager;
import pm.ws.PasswordManagerImplService;
import pt.ulisboa.tecnico.seconf.ws.uddi.UDDINaming;

public class Client {
	public static ClientLib main(String[] args) throws Exception {
		// Check arguments
		if (args.length < 3) {
			System.err.println("Argument(s) missing!");
			System.err.printf("Usage: java %s uddiURL name%n", Client.class.getName());
			return null;
		}
		
		String uddiURL = args[0];
		String name = args[1];
		int number_faults = Integer.parseInt(args[2]);
		int N = 3 * number_faults + 1;
		
		UDDINaming uddiNaming = new UDDINaming(uddiURL);

		ArrayList<PasswordManager> portList = new ArrayList<PasswordManager>();
        for(int i=0; i<N; i++){
        	String nameTry = String.format(name, i);
            System.out.printf("Looking for '%s'%n", nameTry);
	        String endpointAddress = uddiNaming.lookup(nameTry);
	
	        if (endpointAddress == null) {
	            System.out.println("Not found!");
	            return null;
	        } else {
	            System.out.printf("Found %s%n", endpointAddress);
	        }
	
	        System.out.println("Creating stub ...");
			PasswordManagerImplService service = new PasswordManagerImplService();
			PasswordManager port = service.getPasswordManagerImplPort();
			portList.add(port);
	        
	        System.out.println("Setting endpoint address ...");
	        BindingProvider bindingProvider = (BindingProvider) port;
	        Map<String, Object> requestContext = bindingProvider.getRequestContext();
	        requestContext.put(ENDPOINT_ADDRESS_PROPERTY, endpointAddress);
	
	        System.out.println("Remote call ...");
        }
     
		return new ClientLib(portList, number_faults);

		// ****** Get Keystore ******
		/*String alias = "client";
		char[] password = "benfica".toCharArray();
		KeyStore ks = KeyStore.getInstance("JCEKS");
		InputStream readStream = new FileInputStream("src/main/resources/KeyStore.jceks");
		ks.load(readStream, password);
		readStream.close();
		/*
		String alias = "selfsigned";
		char[] password = "password".toCharArray();
		FileInputStream readStream = new FileInputStream("KeyStore.jceks");
		
	    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
	    ks.load(readStream, password);
		*/
		// ****************************
		/*
		c.init(ks, alias, password);
		c.register_user();
		c.save_password("facebook.com".getBytes(), "pedro".getBytes(), "seconf".getBytes());
		System.out.println("Ciphered Password: "+Base64.getEncoder().encodeToString("facebook.com".getBytes()));
		System.out.println("Password: "+new String(c.retrieve_password("facebook.com".getBytes(), "pedro".getBytes())));*/
	}
}
