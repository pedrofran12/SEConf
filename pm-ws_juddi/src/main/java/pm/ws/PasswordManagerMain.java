package pm.ws;

import javax.xml.ws.Endpoint;

import pt.ulisboa.tecnico.seconf.ws.uddi.UDDINaming;

public class PasswordManagerMain {

	private static int NUMBER_REPLICAS;
	
	public static void main(String[] args) {
		// Check arguments
		if (args.length < 5) {
			System.err.println("Argument(s) missing!");
			System.err.printf("Usage: java %s uddiURL wsName wsURL%n", PasswordManagerMain.class.getName());
			return;
		}

		String uddiURL = args[0];
		String name = args[1];
		String url = args[2];
		int firstport = Integer.parseInt(args[3]);
		String number_faults = args[4];
		NUMBER_REPLICAS = 3 * Integer.parseInt(number_faults) + 1;		
		execute(uddiURL, name, url, firstport, NUMBER_REPLICAS);
	}

	
	
	
	public static void execute(String uddiURL, String name, String url, int port, int number_of_replicas) {
		Endpoint endpoint = null;
		UDDINaming uddiNaming = null;
		boolean success = true;
		if(number_of_replicas <= 0)
			return;
		String urlTry = String.format(url, port);
		String nameTry = String.format(name, NUMBER_REPLICAS - number_of_replicas);
		try {
			endpoint = Endpoint.create(PasswordManagerImpl.getInstance(port));

			// publish endpoint
			System.out.printf("Starting %s%n", urlTry);
			endpoint.publish(urlTry);

			// publish to UDDI
			System.out.printf("Publishing '%s' to UDDI at %s%n", nameTry, uddiURL);
			uddiNaming = new UDDINaming(uddiURL);
			uddiNaming.rebind(nameTry, urlTry);

			// wait
			System.out.println("Awaiting connections");
			System.out.println("Press enter to shutdown");
			System.in.read();
		} catch (com.sun.xml.ws.server.ServerRtException e) {
			execute(uddiURL, name, url, port + 1, number_of_replicas - 1);
			success = false;
		} catch (Exception e) {
			System.out.printf("Caught exception: %s%n", e);
			e.printStackTrace();

		} finally {
			try {
				if (endpoint != null && success) {
					// stop endpoint
					endpoint.stop();
					System.out.printf("Stopped %s%n", urlTry);
				}
			} catch (Exception e) {
				System.out.printf("Caught exception when stopping: %s%n", e);
			}
			try {
				if (uddiNaming != null) {
					// delete from UDDI
					uddiNaming.unbind(nameTry);
					System.out.printf("Deleted '%s' from UDDI%n", nameTry);
				}
			} catch (Exception e) {
				System.out.printf("Caught exception when deleting: %s%n", e);
			}
		}

	}

}
