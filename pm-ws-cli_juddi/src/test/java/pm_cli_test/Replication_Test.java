package pm_cli_test;

import static javax.xml.ws.BindingProvider.ENDPOINT_ADDRESS_PROPERTY;
import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.nio.file.Files;
import java.security.KeyStore;
import java.util.Map;
import java.util.Properties;
import java.util.Scanner;

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
public class Replication_Test {

	private static ClientLib c;
	private static String alias = "client";

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
		AttackerHandler.setHandler("");
	}

	@AfterClass
	public static void oneTimeTearDown() {
		c.close();
	}
	
	private void enterToContinue() {
		File f = new File("DELETE.ME");
		System.out.println("Delete file DELETE.ME to continue!");
		try {
			f.createNewFile();
			while (f.exists()) {
				Thread.sleep(1000);
			}
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	// ************************************************\\
	// Reborn's Tests \\
	// ************************************************\\
	@Test
	public void testReplication() throws Exception {
		char[] password = "seconf".toCharArray();
		KeyStore ks = getKeyStore("KeyStore-seconf", password);

		c.init(ks, alias, password);
		System.out.println("Kill 1 server");
		enterToContinue();
		c.register_user();
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "arroz de caralho".getBytes());
		System.out.println("Restart first killed server");
		System.out.println("Kill other server");
		enterToContinue();
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "reborn_pwd".getBytes());
		System.out.println("Restart last killed server");
		System.out.println("Kill other server");
		enterToContinue();
		byte[] passwd = c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
		c.close();
		assertEquals("reborn_pwd", new String(passwd));
	}
}
