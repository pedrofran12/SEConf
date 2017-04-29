package pm_cli_test;

import static javax.xml.ws.BindingProvider.ENDPOINT_ADDRESS_PROPERTY;
import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Map;
import java.util.Properties;

import javax.xml.registry.JAXRException;
import javax.xml.ws.BindingProvider;

import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.apache.maven.project.MavenProject;
import org.junit.*;

import pm.cli.Client;
import pm.cli.ClientLib;
import pm.exception.cli.AlreadyExistsLoggedUserException;
import pm.exception.cli.ClientException;
import pm.exception.cli.InvalidDomainException;
import pm.exception.cli.InvalidKeyStoreException;
import pm.exception.cli.InvalidUsernameException;
import pm.handler.AttackerHandler;
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
	private static String aliasSymmetric = "clienthmac";


	@BeforeClass
	public static void oneTimeSetUp() throws Exception {
		
		Model model = null;
		FileReader reader = null;
		MavenXpp3Reader mavenreader = new MavenXpp3Reader();
		try {
		    File pomfile = new File("pom.xml");
			reader = new FileReader(pomfile );
		    model = mavenreader.read(reader);
		    model.setPomFile(pomfile);
		}catch(Exception ex){}
		MavenProject project = new MavenProject(model);
		
		Properties p = project.getProperties();
		String uddiName = p.getProperty("uddi.url");
		String name = p.getProperty("ws.name");
		String faults = p.getProperty("ws.number.faults");
		
		
		c = Client.main(new String[]{uddiName, name, faults});

	}

	public KeyStore getKeyStore(String fileName, char[] passwd) {
		KeyStore k = null;
		try {
			k = KeyStore.getInstance("JCEKS");
			InputStream readStream = new FileInputStream("src/main/resources/" + fileName + ".jceks");
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
		AttackerHandler.setHandler("");
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

		c.init(ks, alias, aliasSymmetric, password);
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
		c.init(ks, alias, aliasSymmetric, password);
		c.init(null, null, null, null);
	}

	@Test(expected = InvalidKeyStoreException.class) // A corrigir
	public void testRegisterUser_InvalidKey()
			throws ClientException, InvalidKeyException_Exception, KeyAlreadyExistsException_Exception {
		c.init(null, alias, aliasSymmetric, "hi".toCharArray());
		c.register_user();
	}

	@Test(expected = KeyAlreadyExistsException_Exception.class) 
	public void testRegisterUser_KeyAlreadyExists()
			throws ClientException, InvalidKeyException_Exception, KeyAlreadyExistsException_Exception {
		char[] password = "reborn".toCharArray();
		KeyStore ks = getKeyStore("KeyStore-reborn", password);
		c.init(ks, alias, aliasSymmetric, password);
		c.register_user();
		c.register_user();
	}

	@Test(expected = InvalidDomainException.class)
	public void testSavePasswordInvalidDomain() throws ClientException, InvalidKeyException_Exception,
			InvalidDomainException_Exception, InvalidUsernameException_Exception, InvalidPasswordException_Exception {
		char[] password = "luisrafael".toCharArray();
		KeyStore ks = getKeyStore("KeyStore-luisrafael", password);
		c.init(ks, alias, aliasSymmetric, password);
		c.save_password(null, "reborn".getBytes(), "reborn_pwd".getBytes());
	}

	@Test(expected = InvalidUsernameException.class)
	public void testSavePasswordInvalidUsername() throws ClientException, InvalidKeyException_Exception,
			InvalidDomainException_Exception, InvalidUsernameException_Exception, InvalidPasswordException_Exception {
		char[] password = "pedrofran".toCharArray();
		KeyStore ks = getKeyStore("KeyStore-pedrofran", password);
		c.init(ks, alias, aliasSymmetric, password);
		c.save_password("facebook.com".getBytes(), null, "reborn_pwd".getBytes());
	}

	@Test(expected = InvalidDomainException.class)
	public void testRetrievePasswordInvalidDomain() throws ClientException, InvalidKeyException_Exception,
			KeyAlreadyExistsException_Exception, InvalidDomainException_Exception, InvalidUsernameException_Exception,
			InvalidPasswordException_Exception, UnknownUsernameDomainException_Exception {
		char[] password = "augusto".toCharArray();
		KeyStore ks = getKeyStore("KeyStore-augusto", password);
		c.init(ks, alias, aliasSymmetric, password);
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
		c.init(ks, alias, aliasSymmetric, password);
		c.register_user();
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "reborn_pwd".getBytes());
		c.retrieve_password("facebook.com".getBytes(), null);
	}

}
