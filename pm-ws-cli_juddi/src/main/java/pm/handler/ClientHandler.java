package pm.handler;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.util.Iterator;
import java.util.Set;
import java.util.Date;
import java.net.URL;

import javax.xml.soap.SOAPHeader;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.jws.HandlerChain;
import javax.xml.soap.*;
import javax.xml.ws.BindingProvider;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.MessageContext.Scope;
import javax.xml.ws.handler.soap.*;

import pm.cli.SecureClient;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;

//Nonce + Timestamp
import java.net.InetAddress;
import java.nio.file.Files;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Timestamp;

import org.apache.commons.net.ntp.NTPUDPClient;
import org.apache.commons.net.ntp.TimeInfo;
import org.w3c.dom.NodeList;

@HandlerChain(file = "/handler-chain.xml")
public class ClientHandler implements SOAPHandler<SOAPMessageContext> {
	public static final String WRITE_IDENTIFIER_RESPONSE_PROPERTY = "write.identifer.property";

	public static final String HEADER_DSIGN = "dsign";
	public static final String HEADER_DSIGN_NS = "urn:dsign";
    
	public static final String HEADER_MAC_KEY = "mac-key";
    public static final String HEADER_MAC_KEY_NS = "urn:mac-key"; 
    
	public static final String HEADER_MAC = "mac";
    public static final String HEADER_MAC_NS = "urn:mac";     
	
    public static final String HEADER_NONCE = "nonce";
    public static final String HEADER_NONCE_NS = "urn:nonce";
    
    public static final String HEADER_TIMESTAMP = "timestamp";
    public static final String HEADER_TIMESTAMP_NS = "urn:timestamp";


    public static final String MAC_KEY_REQUEST_PROPERTY = "mac.key.request.property";
	
    public static final String HEADER_WID = "writeid";
    public static final String HEADER_WID_NS = "urn:writeid";

	private static KeyStore _ks;
	private static String _alias;
	private static char[] _password;
	private PublicKey _serverPublicKey;
	
	
	public void setServerPublicKey(String url) {
		if(_serverPublicKey != null)
			return;	    
		try{
		    int port = new URL(url).getPort();
		    byte[] keyBytes = Files.readAllBytes(new File("ServerPublic" + port + ".key").toPath());
			System.out.println("ServerPublic" + port + ".key");
		    X509EncodedKeySpec spec =
		      new X509EncodedKeySpec(keyBytes);
		    KeyFactory kf = KeyFactory.getInstance("RSA");
		    _serverPublicKey = kf.generatePublic(spec);
		}
		catch(Exception e){
		}
	}

	
	public static void setHandler(KeyStore ks, String alias, char[] password){
		_ks = ks;
		_alias = alias;
		_password = password;
	}

	@Override
    public boolean handleMessage(SOAPMessageContext smc) {
        Boolean outbound = (Boolean) smc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
        String operation = smc.get(MessageContext.WSDL_OPERATION).toString();
        System.out.println("\nOutbound = " + outbound);
        System.out.println("Method = " + operation+"\n");

        setServerPublicKey(smc.get(BindingProvider.ENDPOINT_ADDRESS_PROPERTY).toString());
        getMessage(smc);
        try {
            if (outbound) {
            	// send write identifier
            	if (operation.endsWith("put")) {
					String wid = (String) smc.get(WRITE_IDENTIFIER_RESPONSE_PROPERTY);
					addHeaderSM(smc, HEADER_WID,HEADER_WID_NS, wid);
                }
            	
            	// Generate MAC key for integrity purposes on the response message
            	byte[] macKey = generateMacKey();
                addHeaderSM(smc, HEADER_MAC_KEY, HEADER_MAC_KEY_NS, printHexBinary(cipher(macKey)));
            	smc.put(MAC_KEY_REQUEST_PROPERTY, macKey);
            	smc.setScope(MAC_KEY_REQUEST_PROPERTY, Scope.HANDLER);
                
                // NONCE + Timestamp //
                int nonce = generateNonce();
                long ts = generateTimestamp();
                System.out.println("\nNonce: "+nonce);
                System.out.println("Timestamp: "+new Date(ts));
                addHeaderSM(smc,HEADER_NONCE,HEADER_NONCE_NS,""+nonce);
                addHeaderSM(smc,HEADER_TIMESTAMP,HEADER_TIMESTAMP_NS,""+ts);

                final String plainText = getMessage(smc);
                final byte[] plainBytes = plainText.getBytes();

                // SEGURANCA : DSIGN
                // make DSIGN
				byte[] cipherDigest = makeSignature(plainBytes);

                addHeaderSM(smc, HEADER_DSIGN, HEADER_DSIGN_NS, printHexBinary(cipherDigest));
                System.out.println(getMessage(smc));
            } 
            else {
                // message that is going to be sent from server to client
            	System.out.println(getMessage(smc));

                // Get MAC value
                String mac = getHeaderElement(smc, HEADER_MAC, HEADER_MAC_NS);

                // SOAP Message does not have MAC
            	if (mac == null)
            	    return false;

                // Remove from Header MAC components
            	SOAPHeader header = smc.getMessage().getSOAPPart().getEnvelope().getHeader();
            	NodeList nl = header.getChildNodes();
            	for (int i = 0; i < nl.getLength(); i++) {
            	    if (nl.item(i).getNodeName().equals("d:" + HEADER_MAC)) {
            	        header.removeChild(nl.item(i));
            	    }
            	}
            	header.normalize();

                // SOAP Message in bytes without MAC from Header
            	byte[] plainBytes = getMessage(smc).getBytes();

                // SEGURANCA : MAC
            	// make MAC
            	byte[] cipherDigest = parseHexBinary(mac);

                // verify the MAC
            	byte[] macKey = (byte[]) smc.get(MAC_KEY_REQUEST_PROPERTY);
            	boolean result = verifyMAC(macKey, cipherDigest, plainBytes);
            	System.out.println("\nMAC is " + (result ? "right" : "wrong"));

            	if (!result) {
            	   return false;
            	}
            	
            	// receive write identifier
            	if (operation.endsWith("get")) {
	                String wid = getHeaderElement(smc, HEADER_WID, HEADER_WID_NS);
	                smc.put(WRITE_IDENTIFIER_RESPONSE_PROPERTY, wid);
	                smc.setScope(WRITE_IDENTIFIER_RESPONSE_PROPERTY, Scope.APPLICATION);
                }
            }
        } catch (Exception e) {
            System.out.print("Caught exception in handleMessage: ");
            System.out.println(e);
            System.out.println("Continue normal processing...");
            e.printStackTrace();
        }
        System.out.println(String.format("%"+40+"s", "").replace(" ", "="));
        return true;
    }

	@Override
	public boolean handleFault(SOAPMessageContext smc) {
		Boolean outbound = (Boolean) smc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (outbound) return true;
		
		System.out.println("\n\nFault detected:");
		System.out.println(getMessage(smc));
		
		try {
	        // Get MAC value
	        String mac = getHeaderElement(smc, HEADER_MAC, HEADER_MAC_NS);
	
	        // SOAP Message does not have MAC
	    	if (mac == null)
	    	    return false;
	
	        // Remove from Header MAC components
	    	SOAPHeader header = smc.getMessage().getSOAPPart().getEnvelope().getHeader();
	    	NodeList nl = header.getChildNodes();
	    	for (int i = 0; i < nl.getLength(); i++) {
	    	    if (nl.item(i).getNodeName().equals("d:" + HEADER_MAC)) {
	    	        header.removeChild(nl.item(i));
	    	    }
	    	}
	    	header.normalize();
	
	        // SOAP Message in bytes without MAC from Header
	    	byte[] plainBytes = getMessage(smc).getBytes();
	
	        // SEGURANCA : MAC
	    	// make MAC
	    	byte[] cipherDigest = parseHexBinary(mac);
	
	        // verify the MAC
	    	byte[] macKey = (byte[]) smc.get(MAC_KEY_REQUEST_PROPERTY);
	    	boolean result = verifyMAC(macKey, cipherDigest, plainBytes);
	    	System.out.println("\nMAC is " + (result ? "right" : "wrong"));
	
	    	return result;
		} catch (Exception e) {
			e.printStackTrace();
			return false;
		}
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
				System.out.println("Header not found: " + header);
				return null;
			}

			// get first header element
			Name name = se.createName(header, "d", headerNS);
			Iterator it = sh.getChildElements(name);
			// check header element
			if (!it.hasNext()) {
				System.out.println("Header element not found: " + headerNS);
				return null;
			}
			SOAPElement element = (SOAPElement) it.next();
			// get header element value
			String value = element.getValue();

			// print received header
			System.out.println("\nHeader value is " + value);
			return value;
			
		} catch (Exception e) {
			System.out.println("Erro getHeaderElement");
		}
		return null;
	}
	
    private int generateNonce() throws NoSuchAlgorithmException{
        //generate new nonce
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG"); 
        int nonce = random.nextInt(Integer.MAX_VALUE);
        return nonce;
    }

    //return number of milliseconds since January 1, 1970, 00:00:00 GMT
    private long generateTimestamp(){
        String[] hosts = new String[]{
    			"ntp1.tecnico.ulisboa.pt",
    			"ntp2.tecnico.ulisboa.pt",
        		"1.europe.pool.ntp.org",
        		"2.europe.pool.ntp.org",
        		"0.europe.pool.ntp.org",
        		"0.pt.pool.ntp.org"
        };
        TimeInfo ti = null;
        
        NTPUDPClient timeClient = new NTPUDPClient();
        timeClient.setDefaultTimeout(5000); //after 5 seconds no reply
        
        for(String host : hosts){
            try{
                InetAddress hostAddr = InetAddress.getByName(host);
                System.out.println("\nConnected to>" + hostAddr.getHostName() + "/" + hostAddr.getHostAddress()+"\n");
                ti = timeClient.getTime(hostAddr);
                break;
                
            }catch(Exception e){
                ti = null;
                //continue next host
                //e.printStackTrace();
            }
        }
        timeClient.close();
        if(ti!=null){
            return ti.getReturnTime();
        }
        else{
            //generate new ts
            Timestamp ts = new Timestamp(System.currentTimeMillis());
            return ts.getTime();
        }
    }
    
	private byte[] makeSignature(byte[] data) throws Exception{
		return SecureClient.makeSignature(_ks, _alias, _password, data);
	}
	
	private boolean verifySignature(byte[] signature, byte[] data) throws Exception{
		return SecureClient.verifySignature(_ks, _alias, _password, signature, data);
	}
	
	private byte[] makeMAC(byte[] secretKeyByte, byte[] data) throws Exception{
		SecretKey key = new SecretKeySpec(secretKeyByte, 0, secretKeyByte.length, SecureClient.MAC);
		return SecureClient.makeMAC(key, data);
	}
	
	private boolean verifyMAC(byte[] secretKeyByte, byte[] mac, byte[] data) throws Exception{
		SecretKey key = new SecretKeySpec(secretKeyByte, 0, secretKeyByte.length, SecureClient.MAC);
		return SecureClient.verifyMAC(key, mac, data);
	}
	
	private byte[] generateMacKey() throws Exception{
		SecretKey k = SecureClient.generateMacKey();
		System.out.println("mac key generated: " + printHexBinary(k.getEncoded()));
		return k.getEncoded();
	}
	
	private byte[] cipher(byte[] data) throws Exception{
		return SecureClient.cipher(_serverPublicKey, data);
	}
}
