package pm_cli_test;

import static org.junit.Assert.assertEquals;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.util.Properties;

import org.apache.maven.model.Model;
import org.apache.maven.model.io.xpp3.MavenXpp3Reader;
import org.apache.maven.project.MavenProject;
import org.junit.*;

import pm.cli.Client;
import pm.cli.ClientLib;
import pm.cli.SecureClient;
import pm.exception.cli.InsufficientResponsesException;
import pm.handler.AttackerHandler;

/**
 * Integration Test suite
 */
public class Replication_Test {

	private static ClientLib c;
	private static String alias = "client";
	private static String faults = "-1";

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
		faults = p.getProperty("ws.number.faults");
		
		
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
	
	private PrivateKey getPrivateKey() {
		try {
			return SecureClient.getPrivateKey(
					getKeyStore("KeyStore-adolfo", "adolfo".toCharArray()),
					alias, "adolfo".toCharArray());
		} catch (Exception e) {
			return null;
		}
	}
	
	@Before
	public void beforeTest() {
		AttackerHandler.setHandler("");
	}

	@After
	public void afterTest() {
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
			e.printStackTrace();
		}
	}

	// ************************************************\\
	// Reborn's Tests \\
	// ************************************************\\
	@Test
	public void testReplication() throws Exception {
		System.out.println("\n\n\n\n\nKill " + faults + " server(s)");
		enterToContinue();
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "arroz".getBytes());
		System.out.println("\n\n\n\n\nRestart first killed server(s)");
		System.out.println("Kill other server(s)");
		enterToContinue();
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "reborn_pwd".getBytes());
		System.out.println("\n\n\n\n\nRestart last killed server(s)");
		System.out.println("Kill other server(s)");
		enterToContinue();
		byte[] passwd = c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
		c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
		assertEquals("reborn_pwd", new String(passwd));
	}
	
	@Test(expected = InsufficientResponsesException.class)
	public void testDelayedMessage() throws Exception {
		AttackerHandler.setHandler("response-delay");
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "arroz".getBytes());
	}
	
	@Test
	public void testChangeWidValue() throws Exception {
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "arroz2".getBytes());
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "arroz1".getBytes());
		AttackerHandler.setHandler("change-wid-value", getPrivateKey());
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "arroz".getBytes());
		AttackerHandler.setHandler("");
		byte[] passwd = c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
		assertEquals("arroz1", new String(passwd));
	}
	
	@Test
	public void testTieBreakHigh() throws Exception {
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "arroz1".getBytes());
		AttackerHandler.setHandler("tie-break-high", getPrivateKey());
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "arroz".getBytes());
		AttackerHandler.setHandler("");
		byte[] passwd = c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
		assertEquals("arroz", new String(passwd));
	}
	
	@Test
	public void testTieBreakLow() throws Exception {
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "arroz1".getBytes());
		AttackerHandler.setHandler("tie-break-low", getPrivateKey());
		c.save_password("facebook.com".getBytes(), "reborn".getBytes(), "arroz".getBytes());
		AttackerHandler.setHandler("");
		byte[] passwd = c.retrieve_password("facebook.com".getBytes(), "reborn".getBytes());
		assertEquals("arroz1", new String(passwd));
	}
}
