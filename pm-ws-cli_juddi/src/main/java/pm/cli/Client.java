package pm.cli;

import java.security.KeyStore;
import java.util.*;
import javax.xml.ws.*;
import static javax.xml.ws.BindingProvider.ENDPOINT_ADDRESS_PROPERTY;

import pt.ulisboa.tecnico.seconf.ws.uddi.UDDINaming;

import pm.ws.*;
//import pm.exeception.*; // classes generated from WSDL

public class Client {

    private PasswordManager pm;
    private Scanner keyboardSc;
    
    
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
        
    }
    
    public void save_password(byte[] domain, byte[] username, byte[] password){
        
    }
    
    public byte[] retrieve_password(byte[] domain, byte[] username){
        
        return null;
    }

   
}
