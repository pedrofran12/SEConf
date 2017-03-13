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

import pm.cli.ClientLib;
import pm.exception.cli.AlreadyExistsLoggedUserException;
import pm.exception.cli.ClientException;
import pm.exception.cli.InvalidDomainException;
import pm.exception.cli.InvalidKeyStoreException;
import pm.exception.cli.InvalidUsernameException;
import pm.ws.InvalidDomainException_Exception;
import pm.ws.InvalidKeyException_Exception;
import pm.ws.InvalidPasswordException_Exception;
import pm.ws.InvalidUsernameException_Exception;
import pm.ws.KeyAlreadyExistsException_Exception;
import pm.ws.PasswordManager;
import pm.ws.PasswordManagerImplService;
import pm.ws.UnknownUsernameDomainException_Exception;

import pt.ulisboa.tecnico.seconf.ws.uddi.UDDINaming;

/**
 * Integration Test suite
 */
public class Client_Test {

	private static ClientLib c;
	private static String alias = "client";


	@BeforeClass
	public static void oneTimeSetUp() throws JAXRException {
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
		// ********** Open Keystore **************** //

		// ****************************
		c = new ClientLib(port);

	}

	public KeyStore getKeyStore(String fileName, char[] passwd) {
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

	@After
	public void afterTest() {
		c.close();
	}

	@AfterClass
	public static void oneTimeTearDown() {
		c.close();
	}

	// ************************************************\\
	// Reborn's Tests \\
	// ************************************************\\
	@Test
	public void testClient() throws Exception {
		char[] password = "seconf".toCharArray();
		KeyStore ks = getKeyStore("KeyStore-seconf", password);

		c.init(ks, alias, password);
		c.register_user();
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "reborn_pwd".getBytes());
		byte[] passwd = c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
		c.close();
		assertEquals("reborn_pwd", new String(passwd));
	}

	@Test(expected = AlreadyExistsLoggedUserException.class)
	public void testInvalidInit() throws ClientException {
		char[] password = "benfica".toCharArray();
		KeyStore ks = getKeyStore("KeyStore", "benfica".toCharArray());
		c.init(ks, alias, password);
		c.init(null, null, null);
	}

	@Test(expected = InvalidKeyStoreException.class) // A corrigir
	public void testRegisterUser_InvalidKey()
			throws ClientException, InvalidKeyException_Exception, KeyAlreadyExistsException_Exception {
		c.init(null, alias, "hi".toCharArray());
		c.register_user();
	}

	@Test(expected = KeyAlreadyExistsException_Exception.class) // com.sun.xml.ws.fault.ServerSOAPFaultException
																// =
																// KeyAlreadyExists!
	public void testRegisterUser_KeyAlreadyExists()
			throws ClientException, InvalidKeyException_Exception, KeyAlreadyExistsException_Exception {
		char[] password = "reborn".toCharArray();
		KeyStore ks = getKeyStore("KeyStore-reborn", password);
		c.init(ks, alias, password);
		c.register_user();
		c.register_user();
	}

	@Test(expected = InvalidDomainException.class)
	public void testSavePasswordInvalidDomain() throws ClientException, InvalidKeyException_Exception,
			InvalidDomainException_Exception, InvalidUsernameException_Exception, InvalidPasswordException_Exception {
		char[] password = "luisrafael".toCharArray();
		KeyStore ks = getKeyStore("KeyStore-luisrafael", password);
		c.init(ks, alias, password);
		c.save_password(null, "reborn".getBytes(), "reborn_pwd".getBytes());
	}

	@Test(expected = InvalidUsernameException.class)
	public void testSavePasswordInvalidUsername() throws ClientException, InvalidKeyException_Exception,
			InvalidDomainException_Exception, InvalidUsernameException_Exception, InvalidPasswordException_Exception {
		char[] password = "pedrofran".toCharArray();
		KeyStore ks = getKeyStore("KeyStore-pedrofran", password);
		c.init(ks, alias, password);
		c.save_password("facebook.com".getBytes(), null, "reborn_pwd".getBytes());
	}

	@Test(expected = InvalidDomainException.class)
	public void testRetrievePasswordInvalidDomain() throws ClientException, InvalidKeyException_Exception,
			KeyAlreadyExistsException_Exception, InvalidDomainException_Exception, InvalidUsernameException_Exception,
			InvalidPasswordException_Exception, UnknownUsernameDomainException_Exception {
		char[] password = "augusto".toCharArray();
		KeyStore ks = getKeyStore("KeyStore-augusto", password);
		c.init(ks, alias, password);
		c.register_user();
		c.save_password("facebook.com".getBytes(), "augusto".getBytes(), "augusto".getBytes());

		c.retrieve_password(null, "adolfo".getBytes());
	}

	@Test(expected = InvalidUsernameException.class)
	public void testRetrievePasswordInvalidUsername() throws ClientException, InvalidKeyException_Exception,
			KeyAlreadyExistsException_Exception, InvalidDomainException_Exception, InvalidUsernameException_Exception,
			UnknownUsernameDomainException_Exception, InvalidPasswordException_Exception {
		char[] password = "alejandro".toCharArray();
		KeyStore ks = getKeyStore("KeyStore-alejandro", password);
		c.init(ks, alias, password);
		c.register_user();
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "reborn_pwd".getBytes());
		c.retrieve_password("facebook.com".getBytes(), null);
	}

}
