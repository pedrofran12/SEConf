package pm.cli;

import java.security.cert.Certificate;
import java.security.Key;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.*;
import javax.xml.ws.*;
import static javax.xml.ws.BindingProvider.ENDPOINT_ADDRESS_PROPERTY;

import pt.ulisboa.tecnico.sdis.ws.uddi.UDDINaming;

import pm.ws.*;
//import pm.exeception.*; // classes generated from WSDL

public class Client {

    private PasswordManager pm;
    private Scanner keyboardSc;
    private KeyStore _ks;
    
    
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

        Client g = new Client(port);
        
        g.doCode();
    }

    private void doCode(){
        //Here is the code for your test//
        //just do: pm.something();
    }
    





    public Client(PasswordManager port) {
        this.pm = port;
        keyboardSc = new Scanner(System.in);
    }



    public void init(KeyStore ks /*, ....*/){
        
    }
    
    public void register_user(){
        Key k = getPublicKey();
    	pm.register(k);
    }
    
    public void save_password(byte[] domain, byte[] username, byte[] password){
        
    }
    
    public byte[] retrieve_password(byte[] domain, byte[] username){
        
        return null;
    }


    private void setKeyStore(KeyStore k){
    	_ks = k;
    }
    
    private KeyStore getKeyStore(){
    	return _ks;
    }
    
    private Key getPublicKey() {
    	KeyStore keystore = getKeyStore();
    	String alias = "myalias";
    	Key key = keystore.getKey(alias, "password".toCharArray());
    	if (key instanceof PrivateKey) {
    	      // Get certificate of public key
    	      Certificate cert = keystore.getCertificate(alias);

    	      // Get public key
    	      PublicKey publicKey = cert.getPublicKey();
    	      return publicKey;
    	 }
    	
    	throw new Exception("key");
    }
}
