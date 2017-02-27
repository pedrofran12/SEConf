package pt.ulisboa.tecnico.sdis.ws.uddi;

import java.net.PasswordAuthentication;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;

import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.xml.registry.BulkResponse;
import javax.xml.registry.BusinessLifeCycleManager;
import javax.xml.registry.BusinessQueryManager;
import javax.xml.registry.Connection;
import javax.xml.registry.ConnectionFactory;
import javax.xml.registry.FindQualifier;
import javax.xml.registry.JAXRException;
import javax.xml.registry.JAXRResponse;
import javax.xml.registry.RegistryService;
import javax.xml.registry.infomodel.Key;
import javax.xml.registry.infomodel.Organization;
import javax.xml.registry.infomodel.Service;
import javax.xml.registry.infomodel.ServiceBinding;

/**
 * This class defines simple methods to bind UDDI organizations to URL
 * addresses: list, lookup, unbind, bind, rebind. It is inspired by the
 * java.rmi.Naming class.<br />
 * <br />
 * To achieve greater control of the underlying registry, the JAX-R API should
 * be used instead.<br />
 * <br />
 * 
 * @author Miguel Pardal
 */
public class UDDINaming {

	/** JAX-R query object */
	private BusinessQueryManager bqm;
	/** JAX-R update object */
	private BusinessLifeCycleManager blcm;

	/** JAX-R connection factory */
	private ConnectionFactory connFactory;
	/** JAX-R connection */
	private Connection conn;

	/** UDDI URL */
	private String url;

	/** UDDI user name */
	private String username = "username";
	/** UDDI user password */
	private char[] password = "password".toCharArray();

	/**
	 * option to establish connection automatically - Should the lookup method
	 * connect automatically? true - yes, false - no
	 */
	private boolean autoConnectFlag;

	/** option to print JNDI and JAX-R debug messages */
	private boolean debugFlag = false;

	/** option to print JNDI and JAX-R trace messages */
	private boolean traceFlag = false;

	//
	// Constructors
	//

	/**
	 * Create an UDDI client configured to access the specified URL. The
	 * connection to the server is managed automatically (auto-connect option is
	 * enabled).
	 */
	public UDDINaming(String uddiURL) throws JAXRException {
		this(uddiURL, true);
	}

	/**
	 * Create an UDDI client configured to access the specified URL and with the
	 * specified auto-connect option.
	 */
	public UDDINaming(String uddiURL, boolean autoConnect) throws JAXRException {
		// UDDI URL validation
		uddiURL = validateAndTrimStringArg(uddiURL, "UDDI URL");
		if (!uddiURL.startsWith("http"))
			throw new IllegalArgumentException("Please provide UDDI server URL in http://host:port format!");

		this.autoConnectFlag = autoConnect;

		try {
			InitialContext context = new InitialContext();
			connFactory = (ConnectionFactory) context.lookup("java:jboss/jaxr/ConnectionFactory");
		} catch (NamingException e) {
			// Could not find using JNDI
			if (debugFlag) {
				System.out.println("Caught " + e);
				if (traceFlag)
					e.printStackTrace(System.out);
			}
			// try factory method from scout implementation
			System.setProperty("javax.xml.registry.ConnectionFactoryClass",
					"org.apache.ws.scout.registry.ConnectionFactoryImpl");
			connFactory = ConnectionFactory.newInstance();
		}

		// define system properties used to perform replacements in uddi.xml
		if (System.getProperty("javax.xml.registry.queryManagerURL") == null)
			System.setProperty("javax.xml.registry.queryManagerURL", uddiURL + "/juddiv3/services/inquiry");

		if (System.getProperty("javax.xml.registry.lifeCycleManagerURL") == null)
			System.setProperty("javax.xml.registry.lifeCycleManagerURL", uddiURL + "/juddiv3/services/publish");

		if (System.getProperty("javax.xml.registry.securityManagerURL") == null)
			System.setProperty("javax.xml.registry.securityManagerURL", uddiURL + "/juddiv3/services/security");

		Properties props = new Properties();
		props.setProperty("scout.juddi.client.config.file", "uddi.xml");
		props.setProperty("javax.xml.registry.queryManagerURL",
				System.getProperty("javax.xml.registry.queryManagerURL"));
		props.setProperty("scout.proxy.uddiVersion", "3.0");
		props.setProperty("scout.proxy.transportClass", "org.apache.juddi.v3.client.transport.JAXWSTransport");
		connFactory.setProperties(props);

		// save URL
		this.url = uddiURL;
	}

	//
	// Accessors
	//

	/** Return UDDI server address */
	public String getUDDIUrl() {
		return url;
	}

	/** Return user name */
	public String getUsername() {
		return username;
	}

	/** Set user name */
	public void setUsername(String username) {
		username = validateAndTrimStringArg(username, "User name");
		this.username = username;
	}

	/** Set password */
	public void setPassword(char[] password) {
		if (password == null)
			throw new IllegalArgumentException("Password cannot be null!");
		this.password = password;
	}

	/** get print debug messages option value */
	public boolean isPrintDebug() {
		return debugFlag;
	}

	/** print debug messages? */
	public void setPrintDebug(boolean debugFlag) {
		this.debugFlag = debugFlag;
	}

	/**
	 * Main method expects two arguments: - UDDI server URL - Organization name
	 * <br />
	 * <br />
	 * Main performs a lookup on UDDI server using the organization name. <br />
	 * If a registration is found, the service URL is printed to standard
	 * output.<br />
	 * If not, nothing is printed.<br />
	 * <br />
	 * Standard error is used to print error messages.<br />
	 */
	public static void main(String[] args) {
		// Check arguments
		if (args.length < 2) {
			System.err.println("Argument(s) missing!");
			System.err.printf("Usage: java %s uddiURL orgName%n", UDDINaming.class.getName());
			return;
		}

		String uddiURL = args[0];
		String orgName = args[1];

		UDDINaming instance;
		try {
			instance = new UDDINaming(uddiURL);
			String url = instance.lookup(orgName);

			if (url != null)
				System.out.println(url);

		} catch (JAXRException e) {
			System.err.print("Caught JAX-R exception! ");
			System.err.println(e);
		}
	}

	//
	// Connection management
	//

	/** Connect to UDDI server */
	public void connect() throws JAXRException {
		conn = connFactory.createConnection();

		// Define credentials
		PasswordAuthentication passwdAuth = new PasswordAuthentication(username, password);
		Set<PasswordAuthentication> creds = new HashSet<PasswordAuthentication>();
		creds.add(passwdAuth);
		conn.setCredentials(creds);

		// Get RegistryService object
		RegistryService rs = conn.getRegistryService();

		// Get QueryManager object (for inquiries)
		bqm = rs.getBusinessQueryManager();

		// get BusinessLifeCycleManager object (for updates)
		blcm = rs.getBusinessLifeCycleManager();
	}

	/** Disconnect from UDDI server */
	public void disconnect() throws JAXRException {
		try {
			if (conn != null)
				conn.close();
		} finally {
			conn = null;
			bqm = null;
			blcm = null;
		}
	}

	/** Disconnect from UDDI server, ignoring JAX-R exceptions */
	public void disconnectQuietly() {
		try {
			disconnect();

		} catch (JAXRException e) {
			// ignore
		}
	}

	/** helper method to automatically connect to registry */
	private void autoConnect() throws JAXRException {
		if (conn == null)
			if (autoConnectFlag)
				connect();
			else
				throw new IllegalStateException("Not connected! Cannot perform operation!");
	}

	/** helper method to automatically disconnect from registry */
	private void autoDisconnect() throws JAXRException {
		if (autoConnectFlag)
			disconnectQuietly();
	}

	//
	// UDDINaming interface
	// Outer methods manage connection and call internal operations
	//

	/**
	 * Returns a collection of records bound to the name. The provided name can
	 * include wild-card characters - % or ? - to match multiple records.
	 */
	public Collection<UDDIRecord> listRecords(String orgName) throws JAXRException {
		orgName = validateAndTrimStringArg(orgName, "Organization name");

		autoConnect();
		try {
			return queryAll(orgName);
		} finally {
			autoDisconnect();
		}
	}

	/**
	 * Returns a collection of URLs bound to the name. The provided name can
	 * include wild-card characters - % or ? - to match multiple records.
	 */
	public Collection<String> list(String orgName) throws JAXRException {
		orgName = validateAndTrimStringArg(orgName, "Organization name");

		Collection<UDDIRecord> records = listRecords(orgName);
		List<String> urls = new ArrayList<>();
		for (UDDIRecord record : records)
			urls.add(record.getUrl());
		return urls;
	}

	/** Returns the first record associated with the specified name */
	public UDDIRecord lookupRecord(String orgName) throws JAXRException {
		orgName = validateAndTrimStringArg(orgName, "Organization name");

		autoConnect();
		try {
			return query(orgName);
		} finally {
			autoDisconnect();
		}
	}

	/** Returns the first URL associated with the specified name */
	public String lookup(String orgName) throws JAXRException {
		orgName = validateAndTrimStringArg(orgName, "Organization name");

		try {
			UDDIRecord record = lookupRecord(orgName);
			if (record == null)
				return null;
			else
				return record.getUrl();
		} catch (Exception e) {
			System.out.println(e);
			e.printStackTrace();
			throw new RuntimeException(e);
		}
	}

	/** Destroys the binding for the specified name */
	public void unbind(String orgName) throws JAXRException {
		orgName = validateAndTrimStringArg(orgName, "Organization name");

		autoConnect();
		try {
			deleteAll(orgName);

		} finally {
			autoDisconnect();
		}
	}

	/** Binds the specified name to a URL */
	public void bind(String orgName, String url) throws JAXRException {
		UDDIRecord record = new UDDIRecord(orgName, url);
		bind(record);
	}

	/** Binds the specified record containing a name and a URL */
	public void bind(UDDIRecord record) throws JAXRException {
		if (record == null)
			throw new IllegalArgumentException("UDDI Record cannot be null!");

		autoConnect();
		try {
			publish(record);

		} finally {
			autoDisconnect();
		}
	}

	/** Rebinds the specified name to a new URL */
	public void rebind(String orgName, String url) throws JAXRException {
		UDDIRecord record = new UDDIRecord(orgName, url);
		rebind(record);
	}

	/** Rebinds the specified record containing a name and a new URL */
	public void rebind(UDDIRecord record) throws JAXRException {
		if (record == null)
			throw new IllegalArgumentException("UDDI Record cannot be null!");

		autoConnect();
		try {
			deleteAll(record.getOrgName());
			publish(record);

		} finally {
			autoDisconnect();
		}
	}

	//
	// private implementation
	//

	/** helper method to validate string and trim its value */
	private String validateAndTrimStringArg(String string, String name) {
		if (string == null)
			throw new IllegalArgumentException(name + " cannot be null!");
		string = string.trim();
		if (string.length() == 0)
			throw new IllegalArgumentException(name + " cannot be empty!");
		return string;
	}

	/** query UDDI and return a list of records */
	private List<UDDIRecord> queryAll(String orgName) throws JAXRException {
		List<UDDIRecord> records = new ArrayList<UDDIRecord>();

		// search by name
		Collection<String> findQualifiers = new ArrayList<String>();
		findQualifiers.add(FindQualifier.SORT_BY_NAME_DESC);

		// query organizations
		Collection<String> namePatterns = new ArrayList<String>();
		namePatterns.add(orgName);

		// perform search
		BulkResponse r = bqm.findOrganizations(findQualifiers, namePatterns, null, null, null, null);
		@SuppressWarnings("unchecked")
		Collection<Organization> orgs = r.getCollection();
		if (debugFlag)
			System.out.printf("Found %d organizations%n", orgs.size());

		for (Organization o : orgs) {

			@SuppressWarnings("unchecked")
			Collection<Service> services = o.getServices();
			if (debugFlag)
				System.out.printf("Found %d services%n", services.size());

			for (Service s : services) {
				@SuppressWarnings("unchecked")
				Collection<ServiceBinding> serviceBindinds = (Collection<ServiceBinding>) s.getServiceBindings();
				if (debugFlag)
					System.out.printf("Found %d service bindings%n", serviceBindinds.size());

				for (ServiceBinding sb : serviceBindinds) {
					String org = o.getName().getValue();
					String url = sb.getAccessURI();
					UDDIRecord record = new UDDIRecord(org, url);
					records.add(record);
				}
			}
		}

		// service binding not found
		if (debugFlag)
			System.out.printf("Returning list with size %d%n", records.size());
		return records;
	}

	/** query UDDI and return first record */
	private UDDIRecord query(String orgName) throws JAXRException {
		List<UDDIRecord> listResult = queryAll(orgName);
		int listResultSize = listResult.size();

		if (listResultSize == 0) {
			// service binding not found
			if (debugFlag)
				System.out.println("Service binding not found; Returning null");
			return null;
		} else {
			if (listResultSize > 1)
				if (debugFlag)
					System.out.printf("Returning first service binding of %d found%n", listResultSize);
			return listResult.iterator().next();
		}
	}

	/** delete all records that match organization name from UDDI */
	private boolean deleteAll(String orgName) throws JAXRException {

		Collection<String> findQualifiers = new ArrayList<String>();
		findQualifiers.add(FindQualifier.SORT_BY_NAME_DESC);

		Collection<String> namePatterns = new ArrayList<String>();
		namePatterns.add(orgName);

		// Search existing
		BulkResponse response = bqm.findOrganizations(findQualifiers, namePatterns, null, null, null, null);
		@SuppressWarnings("unchecked")
		Collection<Organization> orgs = response.getCollection();
		Collection<Key> orgsToDelete = new ArrayList<Key>();

		for (Organization org : orgs)
			orgsToDelete.add(org.getKey());

		if (debugFlag)
			System.out.printf("%d organizations to delete%n", orgsToDelete.size());

		// delete previous registrations
		if (orgsToDelete.isEmpty()) {
			return true;
		} else {
			BulkResponse deleteResponse = blcm.deleteOrganizations(orgsToDelete);
			boolean result = (deleteResponse.getStatus() == JAXRResponse.STATUS_SUCCESS);

			if (debugFlag) {
				if (result) {
					System.out.println("UDDI deregistration completed successfully.");
				} else {
					System.out.println("UDDI error during deregistration.");
				}
			}

			return result;
		}
	}

	/**
	 * publish a record to UDDI with derived service name and binding
	 * description
	 */
	private boolean publish(UDDIRecord record) throws JAXRException {
		// derive other names from organization name
		String serviceName = record.getOrgName() + " service";
		String bindingDesc = serviceName + " binding";

		if (debugFlag) {
			System.out.printf("Derived service name %s%n", serviceName);
			System.out.printf("Derived binding description %s%n", bindingDesc);
		}

		return publish(record.getOrgName(), serviceName, bindingDesc, record.getUrl());
	}

	/**
	 * publish a record to UDDI with provided service name and binding
	 * description
	 */
	private boolean publish(String orgName, String serviceName, String bindingDescription, String bindingURL)
			throws JAXRException {

		// Create organization
		Organization org = blcm.createOrganization(orgName);

		// Create service
		Service service = blcm.createService(serviceName);
		service.setDescription(blcm.createInternationalString(serviceName));
		// Add service to organization
		org.addService(service);
		// Create serviceBinding
		ServiceBinding serviceBinding = blcm.createServiceBinding();
		serviceBinding.setDescription(blcm.createInternationalString(bindingDescription));
		serviceBinding.setValidateURI(false);
		// Define the Web Service endpoint address here
		serviceBinding.setAccessURI(bindingURL);
		if (serviceBinding != null) {
			// Add serviceBinding to service
			service.addServiceBinding(serviceBinding);
		}

		// register new organization/service/serviceBinding
		Collection<Organization> orgs = new ArrayList<Organization>();
		orgs.add(org);
		BulkResponse response = blcm.saveOrganizations(orgs);

		boolean result = (response.getStatus() == JAXRResponse.STATUS_SUCCESS);

		if (debugFlag) {
			if (result) {
				System.out.println("UDDI registration completed successfully.");
			} else {
				System.out.println("UDDI error during registration.");
			}
		}

		return result;
	}

}
