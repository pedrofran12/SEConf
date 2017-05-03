package pm.handler;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.file.Files;
import java.sql.Timestamp;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.Date;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.soap.*;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.MessageContext.Scope;
import javax.xml.ws.handler.soap.*;

import org.apache.commons.net.ntp.NTPUDPClient;
import org.apache.commons.net.ntp.TimeInfo;
import org.omg.Messaging.SyncScopeHelper;
import org.w3c.dom.NodeList;

import pm.ws.SecureServer;
import utilities.ObjectUtil;

import static javax.xml.bind.DatatypeConverter.parseHexBinary;
import static javax.xml.bind.DatatypeConverter.printHexBinary;

public class ServerHandler implements SOAPHandler<SOAPMessageContext> {
	public static final String MAC_KEY_REQUEST_PROPERTY = "mac.key.request.property";
	public static final String WRITE_IDENTIFIER_RESPONSE_PROPERTY = "write.identifer.property";
	
	public static final String HEADER_MAC_DS = "mac-dsign";
	public static final String HEADER_MAC_DS_NS = "urn:mac-dsign";
    
    public static final String HEADER_MAC_KEY = "mac-key";
    public static final String HEADER_MAC_KEY_NS = "urn:mac-key"; 
    
    public static final String HEADER_MAC = "mac";
    public static final String HEADER_MAC_NS = "urn:mac";    
    
    public static final String HEADER_NONCE = "nonce";
    public static final String HEADER_NONCE_NS = "urn:nonce";
    
    public static final String HEADER_TIMESTAMP = "timestamp";
    public static final String HEADER_TIMESTAMP_NS = "urn:timestamp";

    public static final String HEADER_WID = "writeid";
    public static final String HEADER_WID_NS = "urn:writeid";

    
    private static final int NONCE_TIMEOUT = 2*60*1000; //in milliseconds
    
    private HashMap<Integer, Long> nonceMap = new HashMap<Integer, Long>();

    private static PrivateKey _serverPrivateKey;
    
    
    public static void setPrivateKey(String port) {
    	try {
	        byte[] keyBytes = Files.readAllBytes(new File("ServerPrivate" + port + ".key").toPath());
	
	        PKCS8EncodedKeySpec spec =
	          new PKCS8EncodedKeySpec(keyBytes);
	        KeyFactory kf = KeyFactory.getInstance("RSA");
	        _serverPrivateKey = kf.generatePrivate(spec);
    	}
        catch (Exception e) {
        	e.printStackTrace();
        }
    }
    
	@Override
	public boolean handleMessage(SOAPMessageContext smc) {
		Boolean outbound = (Boolean) smc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		String operation = smc.get(MessageContext.WSDL_OPERATION).toString();
		System.out.println("\nOutbound = " + outbound);
		System.out.println("Method = " + operation);
		
		getMessage(smc);
		try {
			if (outbound) {
				// send write identifier
				if (operation.endsWith("get")) {
					String wid = (String) smc.get(WRITE_IDENTIFIER_RESPONSE_PROPERTY);
					addHeaderSM(smc, HEADER_WID,HEADER_WID_NS, wid);
                }
				
				final byte[] plainBytes = getMessage(smc).getBytes();

				// SEGURANCA : MAC
				// make MAC
				byte[] macKey = (byte[]) smc.get(MAC_KEY_REQUEST_PROPERTY);
				System.out.println("outbound key: " + printHexBinary(macKey));
				
				byte[] mac = makeMAC(macKey, plainBytes);
				addHeaderSM(smc, HEADER_MAC, HEADER_MAC_NS, printHexBinary(mac));
				System.out.println(getMessage(smc));
			}
			else {
				// message that is going to be sent from client to server
				System.out.println(getMessage(smc));
				
                //Get generated mac key of client
                String macKeyCipheredText = getHeaderElement(smc, HEADER_MAC_KEY, HEADER_MAC_KEY_NS);
				byte[] macKey = decipher(parseHexBinary(macKeyCipheredText));
			   	
				//Get DSIGN value
				String mac = getHeaderElement(smc, HEADER_MAC, HEADER_MAC_NS);
				String dsign = getHeaderElement(smc, HEADER_MAC_DS, HEADER_MAC_DS_NS);

				//SOAP Message does not have DSIGN
				if (mac == null) {
					return false;
				}

				//Remove DSIGN from header
				SOAPHeader header = smc.getMessage().getSOAPPart().getEnvelope().getHeader();
				NodeList nl = header.getChildNodes();
				for (int i = 0; i < nl.getLength(); i++) {
					//if (nl.item(i).getNodeName().equals("d:" + HEADER_DSIGN)) {
					if (nl.item(i).getNodeName().equals("d:" + HEADER_MAC)) {
						header.removeChild(nl.item(i));
					}
				}
				header.normalize();

				//SOAP Message bytes without DSIGN
				final byte[] plainBytes = getMessage(smc).getBytes();

				//Client's Key
				byte[] byteElement = getBodyElement(smc, "key").getBytes();
				byte[] publicKeyClient = Base64.getDecoder().decode(byteElement);				
				
				//Generate's DSIGN
				byte[] cipherDigest = parseHexBinary(mac);

				// verify the DSIGN
				//boolean result = verifySignature(publicKeyClient, cipherDigest, plainBytes);
				
				boolean result = verifyMAC(macKey, cipherDigest, plainBytes) && 
						verifySignature(publicKeyClient, parseHexBinary(dsign), parseHexBinary(macKeyCipheredText));
				System.out.println("MAC is " + (result ? "right" : "wrong"));

				if (!result) {
					return false;
				}
				
				//Verify Nonce+Timestamp
				int nonce = Integer.parseInt(getHeaderElement(smc, HEADER_NONCE ,HEADER_NONCE_NS)); //need to check with send 
                long ts = Long.parseLong(getHeaderElement(smc,HEADER_TIMESTAMP,HEADER_TIMESTAMP_NS));
                System.out.println("\nNonce: "+nonce);
                System.out.println("Timestamp: "+ new Date(ts));
                
                if(!isNonceValid(nonce,ts)) { //if nonce not valid returns false! (discards message)
                    System.out.println(">>> Replay attack detected");
                	return false;
                }

                //Save MAC key
				smc.put(MAC_KEY_REQUEST_PROPERTY, macKey);
				smc.setScope(MAC_KEY_REQUEST_PROPERTY, Scope.HANDLER);
                
				// receive write identifier 
                if (operation.endsWith("put")) {
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
		// TODO Auto-generated method stub
		Boolean outbound = (Boolean) smc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		if (!outbound) return true;
		
		try {
			final byte[] plainBytes = getMessage(smc).getBytes();

			// SEGURANCA : MAC
			// make MAC
			byte[] macKey = (byte[]) smc.get(MAC_KEY_REQUEST_PROPERTY);
			System.out.println("outbound key: " + printHexBinary(macKey));
			
			byte[] mac = makeMAC(macKey, plainBytes);
			addHeaderSM(smc, HEADER_MAC, HEADER_MAC_NS, printHexBinary(mac));
			
			System.out.println("\n\nFault detected:");
			System.out.println(getMessage(smc));
			
			return true;
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

			return value;

		} catch (Exception e) {
			System.out.println("Erro getHeaderElement");
		}
		return null;
	}

	/**
	 * metodo para obter um elemento com um dado nome 'Header', um dado
	 * namespace 'headerNS' ao cabecalho de uma SOAPMessage 'smc'
	 */
	private String getBodyElement(SOAPMessageContext smc, String tag) {
		try {
			// get SOAP envelope header
			SOAPMessage msg = smc.getMessage();
			SOAPPart sp = msg.getSOAPPart();
			SOAPEnvelope se = sp.getEnvelope();
			SOAPBody sh = se.getBody();
			return findAttributeRecursive(sh, tag);
		} catch (Exception e) {
			System.out.println("Erro getHeaderElement");
		}
		return null;
	}

	private String findAttributeRecursive(SOAPElement element, String tag) {
		NodeList nl = element.getChildNodes();
		for (int i = 0; i < nl.getLength(); i++) {
			if (nl.item(i).getNodeType() == Node.ELEMENT_NODE) {
				SOAPElement se = (SOAPElement) nl.item(i);
				if (se.getNodeName().equals(tag)) {
					return se.getValue();
				}
				String atr = findAttributeRecursive(se, tag);
				if (atr != null) {
					return atr;
				}
			}
		}
		return null;
	}
	
	private byte[] makeSignature(byte[] privateKeyByte, byte[] data) throws Exception{
		PrivateKey privateKey = ObjectUtil.readObjectBytes(privateKeyByte, PrivateKey.class);
		return SecureServer.makeSignature(privateKey, data);
	}
	
	private boolean verifySignature(byte[] publicKeyByte, byte[] signature, byte[] data) throws Exception{
		PublicKey publicKey = ObjectUtil.readObjectBytes(publicKeyByte, PublicKey.class);
		return SecureServer.verifySignature(publicKey, signature, data);
	}

	private byte[] makeMAC(byte[] secretKeyByte, byte[] data) throws Exception{
		SecretKey key = new SecretKeySpec(secretKeyByte, 0, secretKeyByte.length, SecureServer.MAC);
		return SecureServer.makeMAC(key, data);
	}
	
	private boolean verifyMAC(byte[] secretKeyByte, byte[] mac, byte[] data) throws Exception{
		SecretKey key = new SecretKeySpec(secretKeyByte, 0, secretKeyByte.length, SecureServer.MAC);
		return SecureServer.verifyMAC(key, mac, data);
	}
	
	private byte[] decipher(byte[] data) throws Exception{
		return SecureServer.decipher(_serverPrivateKey, data);
	}
	
	
	
	 /*
     * Checks for nonce in map
     * TRUE: 
     *     - Checks for Timestamp of that nonce in map and received_nonce:
     *     True:
     *          - Within 2min: REPLAY ATTACK
     *     FALSE:
     *          - Outdated nonce, i'll update it!
     * False:
     *       -Nonce does not exists, so it's a new... i'll add it!
     */
    private boolean isNonceValid(int nonce, long nTs) {
        
        long time = generateTimestamp();
        checkNonces(time);
        if(!compareTime(time,nTs,NONCE_TIMEOUT)){
            return false;
        } 
        else if (nonceMap.containsKey(nonce)) {
            return false;
        }
        else{
            nonceMap.put(nonce, nTs);
            return true;
        }
    }
    
    /*
     * If ts is older than ts2 = ERROR
     */
    private boolean compareTime(long ts, long ts2, long timeout){
        if (ts2 > ts)
            return false; 
        return (ts - ts2)<=timeout;
    }
    
    private void checkNonces(long timeGenerated){
    	Set<Integer> nonces = new HashSet<>(nonceMap.keySet());
        for(int j : nonces) {
            if(!compareTime(timeGenerated,nonceMap.get(j),NONCE_TIMEOUT))
                nonceMap.remove(j);
        }
    }
    
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

}
