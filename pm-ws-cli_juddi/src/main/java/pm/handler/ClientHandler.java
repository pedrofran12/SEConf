package pm.handler;

import java.io.ByteArrayOutputStream;
import java.security.KeyStore;
import java.util.Iterator;
import java.util.Set;

import javax.xml.soap.SOAPHeader;
import javax.jws.HandlerChain;
import javax.xml.soap.*;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.*;

import pm.cli.SecureClient;

import static javax.xml.bind.DatatypeConverter.printHexBinary;

@HandlerChain(file = "/handler-chain.xml")
public class ClientHandler implements SOAPHandler<SOAPMessageContext> {

	public static final String HEADER_KEY = "key";
	public static final String HEADER_KEY_NS = "urn:key";

	public static final String HEADER_MAC = "mac";
	public static final String HEADER_MAC_NS = "urn:mac";

	private static KeyStore _ks;
	private static String _alias;
	private static char[] _password;
	
	
	public static void setHandler(KeyStore ks, String alias, char[] password){
		_ks = ks;
		_alias = alias;
		_password = password;
	}

	@Override
	public boolean handleMessage(SOAPMessageContext smc) {
		System.out.println(getMessage(smc));

		Boolean outbound = (Boolean) smc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		String operation = smc.get(MessageContext.WSDL_OPERATION).toString();
		System.out.println("Outbound = " + outbound + "\n\n\n\n");
		System.out.println("Method = " + operation + "\n\n\n\n");
		try {
			if (outbound) {

				final String plainText = getMessage(smc);
				final byte[] plainBytes = plainText.getBytes();

				// SEGURANCA : MAC
				//HandlerSecurity security = getHandlerSecurity();
				System.out.println("=======================\n\n\n\n\n");

				// make MAC
				byte[] cipherDigest = makeSignature(plainBytes);

				// verify the MAC
				// boolean result = security.verifyMAC(cipherDigest, plainBytes,
				// key);
				// System.out.println("MAC is " + (result ? "right" : "wrong"));

				addHeaderSM(smc, HEADER_MAC, HEADER_MAC_NS, printHexBinary(cipherDigest));
				System.out.println(getMessage(smc));
			} else {
				// message that is going to be sent from client to server

				// obter mac value
				//String mac = getHeaderElement(smc, HEADER_MAC, HEADER_MAC_NS);

				// SOAP Message nao tem mac
				//if (mac == null)
				//	return false;

				// Remover da Header a componentes MAC
				//SOAPHeader header = smc.getMessage().getSOAPPart().getEnvelope().getHeader();
				//NodeList nl = header.getChildNodes();
				//for (int i = 0; i < nl.getLength(); i++) {
				//	if (nl.item(i).getNodeName().equals("d:" + HEADER_MAC)) {
				//		header.removeChild(nl.item(i));
				//	}
				//}
				//header.normalize();

				// SOAP Message em string sem o elemento MAC da Header
				//final byte[] plainBytes = getMessage(smc).getBytes();

				// SEGURANCA : MAC
				//HandlerSecurity security = getHandlerSecurity();
				//System.out.println("=======================\n\n\n\n\n");

				// make MAC
				//byte[] cipherDigest = parseHexBinary(mac);

				// verify the MAC
				//boolean result = verifySignature(cipherDigest, plainBytes);
				//System.out.println("MAC is " + (result ? "right" : "wrong"));

				//if (!result) {
				//	return false;
				//}
			}

		} catch (Exception e) {
			System.out.print("Caught exception in handleMessage: ");
			System.out.println(e);
			System.out.println("Continue normal processing...");
			e.printStackTrace();
		}

		return true;
	}

	@Override
	public boolean handleFault(SOAPMessageContext smc) {
		// TODO Auto-generated method stub
		return false;
	}

	@Override
	public void close(MessageContext context) {
		// TODO Auto-generated method stub

	}

	@Override
	public Set getHeaders() {
		// TODO Auto-generated method stub
		return null;
	}

	/**
	 * Check the MESSAGE_OUTBOUND_PROPERTY in the context to see if this is an
	 * outgoing or incoming message. Write a brief message to the print stream
	 * and output the message. The writeTo() method can throw SOAPException or
	 * IOException
	 */
	private String getMessage(SOAPMessageContext smc) {
		SOAPMessage message = smc.getMessage();
		try {
			ByteArrayOutputStream out = new ByteArrayOutputStream(0);
			message.writeTo(out);
			return new String(out.toByteArray());

		} catch (Exception e) {
			System.out.printf("Exception in handler: %s%n", e);
		}
		return null;
	}

	/**
	 * metodo para adicionar elemento 'a Header da SOAP Message 'smc' com um
	 * dado nome 'header', um dado namespace 'headNS' e o valor desta componente
	 * 'value'
	 */
	private void addHeaderSM(SOAPMessageContext smc, String header, String headerNS, String value) {
		try {
			// get SOAP envelope
			SOAPMessage msg = smc.getMessage();
			SOAPPart sp = msg.getSOAPPart();
			SOAPEnvelope se = sp.getEnvelope();

			// add header
			SOAPHeader sh = se.getHeader();
			if (sh == null) {
				sh = se.addHeader();
			}

			// add header element (name, namespace prefix, namespace)
			Name name = se.createName(header, "d", headerNS);
			SOAPHeaderElement element = sh.addHeaderElement(name);

			// add header element value
			element.addTextNode(value);

		} catch (SOAPException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	/**
	 * metodo para obter um elemento com um dado nome 'Header', um dado
	 * namespace 'headerNS' ao cabecalho de uma SOAPMessage 'smc'
	 */
	private String getHeaderElement(SOAPMessageContext smc, String header, String headerNS) {
		try {
			// get SOAP envelope header
			SOAPMessage msg = smc.getMessage();
			SOAPPart sp = msg.getSOAPPart();
			SOAPEnvelope se = sp.getEnvelope();
			SOAPHeader sh = se.getHeader();

			// check header
			if (sh == null) {
				System.out.println("Header not found.");
				return null;
			}

			// get first header element
			Name name = se.createName(header, "d", headerNS);
			Iterator it = sh.getChildElements(name);
			// check header element
			if (!it.hasNext()) {
				System.out.println("Header element not found.");
				return null;
			}
			SOAPElement element = (SOAPElement) it.next();
			// get header element value
			String value = element.getValue();

			// print received header
			System.out.println("Header value is " + value);
			return value;
			
		} catch (Exception e) {
			System.out.println("Erro getHeaderElement");
		}
		return null;
	}
	
	private byte[] makeSignature(byte[] data) throws Exception{
		return SecureClient.makeSignature(_ks, _alias, _password, data);
	}
	
	private boolean verifySignature(byte[] signature, byte[] data) throws Exception{
		return SecureClient.verifySignature(_ks, _alias, _password, signature, data);
	}
}
