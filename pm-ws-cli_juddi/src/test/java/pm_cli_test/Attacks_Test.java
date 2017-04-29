package pm_cli_test;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.security.KeyStore;
import java.util.Properties;

import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.apache.maven.project.MavenProject;
import org.junit.*;
import static org.junit.Assert.*;

import pm.cli.Client;
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
		c.init(getKeyStore("KeyStore-adolfo", "adolfo".toCharArray()), alias, aliasSymmetric, "adolfo".toCharArray());
		c.register_user();

	}

	public static KeyStore getKeyStore(String fileName, char[] passwd) {
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
	
	@Test(expected= Exception.class)
	public void testClient_change_response() throws Exception {
		AttackerHandler.setHandler("password-change");

		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "reborn_pwd".getBytes());
		byte[] passwd = c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
	}
}
