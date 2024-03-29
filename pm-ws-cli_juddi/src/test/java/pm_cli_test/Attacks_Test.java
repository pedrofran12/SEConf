package pm_cli_test;

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

import pm.cli.Client;
import pm.cli.ClientLib;
import pm.handler.AttackerHandler;

/**
 * Integration Test suite
 */
public class Attacks_Test {

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
		c.init(getKeyStore("KeyStore-adolfo", "adolfo".toCharArray()), alias, "adolfo".toCharArray());
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
	public void testClient_mac_remove() throws Exception {
		AttackerHandler.setHandler("mac-remove");
		
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "reborn_pwd".getBytes());
		c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
	}
	
	@Test(expected = Exception.class)
	public void testClient_mac_change() throws Exception {
		AttackerHandler.setHandler("mac-change");

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
		c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
	}
}
