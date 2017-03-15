package pm_cli_test;

import static javax.xml.ws.BindingProvider.ENDPOINT_ADDRESS_PROPERTY;
import static org.junit.Assert.assertEquals;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Map;

import javax.xml.registry.JAXRException;
import javax.xml.ws.BindingProvider;

import org.junit.*;
import static org.junit.Assert.*;


import pm.cli.ClientLib;
import pm.exception.cli.ClientException;
import pm.exception.cli.InvalidPasswordException;
import pm.handler.AttackerHandler;
import pm.ws.InvalidKeyException_Exception;
import pm.ws.KeyAlreadyExistsException_Exception;
import pm.ws.PasswordManager;
import pm.ws.PasswordManagerImplService;

import pt.ulisboa.tecnico.seconf.ws.uddi.UDDINaming;

/**
 * Integration Test suite
 */
public class Attacks_Test {

	private static ClientLib c;
	private static String alias = "client";

	
	@BeforeClass
	public static void oneTimeSetUp() throws JAXRException, ClientException, InvalidKeyException_Exception, KeyAlreadyExistsException_Exception {
		// ********** Connection to Server ********** //
		String url = "http://localhost:8080/pm-ws/endpoint";
		String name = "pm-ws";
		String uddiURL = "http://localhost:9090";

		UDDINaming uddiNaming = new UDDINaming(uddiURL);
		String endpointAddress = uddiNaming.lookup(name);
		PasswordManagerImplService service = new PasswordManagerImplService();
		PasswordManager port = service.getPasswordManagerImplPort();
		BindingProvider bindingProvider = (BindingProvider) port;
		Map<String, Object> requestContext = bindingProvider.getRequestContext();
		requestContext.put(ENDPOINT_ADDRESS_PROPERTY, endpointAddress);
		// ****************************
		
		c = new ClientLib(port);
		c.init(getKeyStore("KeyStore-adolfo", "adolfo".toCharArray()), "client", "adolfo".toCharArray());
		c.register_user();

	}

	public static KeyStore getKeyStore(String fileName, char[] passwd) {
		KeyStore k = null;
		try {
			k = KeyStore.getInstance("JKS");
			InputStream readStream = new FileInputStream("src/main/resources/" + fileName + ".jks");
			k.load(readStream, passwd);
			readStream.close();
		} catch (Exception e) {
			System.out.println("Test Failed");
			e.printStackTrace();
		}
		return k;
	}

	@AfterClass
	public static void oneTimeTearDown() {
		c.close();
	}

	// ************************************************\\
	// Reborn's Tests \\
	// ************************************************\\
	@Test(expected = Exception.class)
	public void testClient_dsign_remove() throws Exception {
		AttackerHandler.setHandler("dsign-remove");
		
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "reborn_pwd".getBytes());
		c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
	}
	
	@Test(expected = Exception.class)
	public void testClient_dsign_change() throws Exception {
		AttackerHandler.setHandler("dsign-change");

		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "reborn_pwd".getBytes());
		c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
	}
	
	@Test(expected = Exception.class)
	public void testClient_msg_change() throws Exception {
		AttackerHandler.setHandler("msg-change");
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "reborn_pwd".getBytes());
		c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
	}
	
	@Test(expected = Exception.class)
	public void testClient_replay_attack() throws Exception {
		AttackerHandler.setHandler("replay-attack");

		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "reborn_pwd".getBytes());
		c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
	}
	
	@Test(expected= InvalidPasswordException.class)
	public void testClient_change_response() throws Exception {
		AttackerHandler.setHandler("password-change");

		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "reborn_pwd".getBytes());
		byte[] passwd = c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
	}
}
