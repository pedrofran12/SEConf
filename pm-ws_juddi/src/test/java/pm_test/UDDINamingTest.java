package pm_test;

import static org.junit.Assert.assertEquals;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import pt.ulisboa.tecnico.seconf.ws.uddi.UDDINaming;

/**
 * Test suite
 */
public class UDDINamingTest {

    // static members

    // one-time initialization and clean-up

    @BeforeClass
    public static void oneTimeSetUp() {

    }

    @AfterClass
    public static void oneTimeTearDown() {

    }

    // members

    String uddiURL = "http://localhost:9090";
    String name = "MyWS";
    String url = "http://host:port/my-ws/endpoint";

    private UDDINaming uddiNaming;

    // initialization and clean-up for each test

    @Before
    public void setUp() throws Exception {
        uddiNaming = new UDDINaming(uddiURL);
    }

    @After
    public void tearDown() {
        uddiNaming = null;
    }

    // tests

    @Test
    public void test() throws Exception {

        // publish to UDDI
        uddiNaming = new UDDINaming(uddiURL);
        uddiNaming.rebind(name, url);

        // query UDDI
        String endpointAddress = uddiNaming.lookup(name);

        assertEquals(/* expected */url, /* actual */endpointAddress);
    }

}
