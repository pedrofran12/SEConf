package pm.handler;

import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.Iterator;
import java.util.Set;

import javax.jws.HandlerChain;
import javax.xml.soap.*;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.*;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;

//Nonce + Timestamp
import java.net.InetAddress;
import java.security.SecureRandom;
import java.sql.Timestamp;

import org.apache.commons.net.ntp.NTPUDPClient;
import org.apache.commons.net.ntp.TimeInfo;
import org.w3c.dom.NodeList;

import pm.cli.ClientLibReplicated;
import pm.cli.SecureClient;
import pm.exception.cli.InvalidKeyStoreException;


@HandlerChain(file = "/handler-chain.xml")
public class AttackerHandler implements SOAPHandler<SOAPMessageContext> {

	public static final String HEADER_DSIGN = "dsign";
	public static final String HEADER_DSIGN_NS = "urn:dsign";

	public static final String HEADER_NONCE = "nonce";
    public static final String HEADER_NONCE_NS = "urn:nonce";
    
    public static final String HEADER_TIMESTAMP = "timestamp";
    public static final String HEADER_TIMESTAMP_NS = "urn:timestamp";
    
    public static final String HEADER_WID = "writeid";
    public static final String HEADER_WID_NS = "urn:writeid";

	private static String TYPE_OF_ATTACK = "";	
	
	private static SOAPMessageContext oldSmc = null;
	
	public static void setHandler(String typeOfAttack){
		TYPE_OF_ATTACK = typeOfAttack;
	}

	@Override
    public boolean handleMessage(SOAPMessageContext smc) {
		Boolean outbound = (Boolean) smc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		String operation = smc.get(MessageContext.WSDL_OPERATION).toString();
		
		getMessage(smc);
		if(outbound){
			switch (TYPE_OF_ATTACK) {
			case "dsign-remove":
				// Remove from Header old DSIGN components
				try {
		        	SOAPHeader header = smc.getMessage().getSOAPPart().getEnvelope().getHeader();
		        	NodeList nl = header.getChildNodes();
		        	for (int i = 0; i < nl.getLength(); i++) {
		        	    if (nl.item(i).getNodeName().equals("d:" + HEADER_DSIGN)) {
		        	        header.removeChild(nl.item(i));
		        	    }
		        	}
		        	header.normalize();
	        	} catch (SOAPException e) {
					e.printStackTrace();
				}
				break;
			case "dsign-change":
				byte[] sig = parseHexBinary(getHeaderElement(smc, HEADER_DSIGN, HEADER_DSIGN_NS));
				sig[0] = (byte) (sig[0] + 1);
	            
				// Remove from Header old DSIGN components
				try {
		        	SOAPHeader header = smc.getMessage().getSOAPPart().getEnvelope().getHeader();
		        	NodeList nl = header.getChildNodes();
		        	for (int i = 0; i < nl.getLength(); i++) {
		        	    if (nl.item(i).getNodeName().equals("d:" + HEADER_DSIGN)) {
		        	        header.removeChild(nl.item(i));
		        	    }
		        	}
		        	header.normalize();
	        	} catch (SOAPException e) {
					e.printStackTrace();
				}
	
				
				addHeaderSM(smc, HEADER_DSIGN, HEADER_DSIGN_NS, printHexBinary(sig));
				break;
			case "msg-change":
				addHeaderSM(smc, HEADER_DSIGN, HEADER_DSIGN_NS, "Hacked");
				break;
			
		    case "replay-attack":
		    	if(oldSmc!=null)
		    		smc.setMessage(oldSmc.getMessage());
	    		else
	    			oldSmc = smc;
				break;
				
		    case "change-wid-value":
		    case "change-wid-force":
		    case "tie-break-high":
		    case "tie-break-low":
		    	if (!operation.endsWith("put")) return true;
		    	try {
		    		String wid = getHeaderElement(smc, HEADER_WID, HEADER_WID_NS);
			    	// 1. remover dsing
			    	SOAPHeader header = smc.getMessage().getSOAPPart().getEnvelope().getHeader();
					NodeList nl = header.getChildNodes();
					for (int i = 0; i < nl.getLength(); i++) {
						if (nl.item(i).getNodeName().equals("d:" + HEADER_DSIGN) ||
								nl.item(i).getNodeName().equals("d:" + HEADER_WID)) {
							header.removeChild(nl.item(i));
						}
					}
					header.normalize();
			    	// 2. novo wid
					if (TYPE_OF_ATTACK.equals("change-wid-force")) {
						wid = "1000:" + wid.split(":", 2)[1];
					} else {
						byte[] domain = Base64.getDecoder().decode(getBodyElement(smc, "arg1").getBytes());
						byte[] username = Base64.getDecoder().decode(getBodyElement(smc, "arg2").getBytes());
						byte[] password = Base64.getDecoder().decode(getBodyElement(smc, "arg3").getBytes());
						int i = 0;
						int t = 618276;
						if (TYPE_OF_ATTACK.startsWith("tie-break")) {
							t = TYPE_OF_ATTACK.endsWith("high") ? Integer.MAX_VALUE : -1;
							i = Integer.parseInt(wid.split(":", 2)[0]) - 1;
						}
						String mac = makeMac(i, t, domain, username, password);
						wid = i + ":" + t + ":" + mac;
					}
					addHeaderSM(smc, HEADER_WID,HEADER_WID_NS, wid);
			    	// 3. recriar dsing
					final String plainText = getMessage(smc);
	                final byte[] plainBytes = plainText.getBytes();

	                // SEGURANCA : DSIGN
	                // make DSIGN
					byte[] cipherDigest = makeSignature(plainBytes);

	                addHeaderSM(smc, HEADER_DSIGN, HEADER_DSIGN_NS, printHexBinary(cipherDigest));
		    	} catch (Exception e) {
		    		e.printStackTrace();
		    	}
				break;
			
			}
		}
		//REQUESTS ARE SENT FROM SERVER TO CLIENT
		else{
			switch (TYPE_OF_ATTACK) {
				case "response-delay":
					try {
						Thread.sleep(ClientLibReplicated.WAITING_TIME + 5000);
					} catch (InterruptedException e) {
						e.printStackTrace();
					}
					break;
				case "password-change":
					if(operation.contains("get")) {
						System.out.println("»»»»»»»»»»»»»»»»»»»»»");
						System.out.println(getMessage(smc));
						setBodyElement(smc, "return");
						System.out.println(getMessage(smc));
						System.out.println("»»»»»»»»»»»»»»»»»»»»»");
					}
					break;
			}
				
		}
			
        return true;
    }

	@Override
	public boolean handleFault(SOAPMessageContext smc) {
		// TODO Auto-generated method stub
		return true;
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
        String[] hosts = new String[]{"0.pt.pool.ntp.org","1.europe.pool.ntp.org","0.europe.pool.ntp.org","2.europe.pool.ntp.org"};
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
    
    
	private void setBodyElement(SOAPMessageContext smc, String tag) {
		try {
			// get SOAP envelope header
			SOAPMessage msg = smc.getMessage();
			SOAPPart sp = msg.getSOAPPart();
			SOAPEnvelope se = sp.getEnvelope();
			SOAPBody sh = se.getBody();
			findAttributeRecursive(sh, tag);
		} catch (Exception e) {
			System.out.println("Erro getHeaderElement");
		}
	}

	private void findAttributeRecursive(SOAPElement element, String tag) {
		NodeList nl = element.getChildNodes();
		for (int i = 0; i < nl.getLength(); i++) {
			if (nl.item(i).getNodeType() == Node.ELEMENT_NODE) {
				SOAPElement se = (SOAPElement) nl.item(i);
				if (se.getNodeName().equals(tag)) {
					String passwordEncoded = se.getValue();
					byte[] passwordCiphered = Base64.getDecoder().decode(passwordEncoded.getBytes());
					passwordCiphered[0] = (byte) (passwordCiphered[0] + 1);
					se.setValue(Base64.getEncoder().encodeToString(passwordCiphered));
					return;
				}
				findAttributeRecursive(se, tag);
			}
		}
	}
	
	private String makeMac(int wid, int tie, byte[]... values) {
		try {
			String toMake = wid + ":" + tie;
			for (byte[] value : values) {
				toMake += ":" + Base64.getEncoder().encodeToString(value);
			}
			byte[] bytesForMac = toMake.getBytes();
			byte[] mac = SecureClient.makeMAC(getSymetricKey(), bytesForMac);
			return Base64.getEncoder().encodeToString(mac);
		} catch (Exception e) {
			return null;
		}
	}
	
	private Key getSymetricKey() {
		String alias = "clienthmac";
		char[] password = "seconf".toCharArray();
		KeyStore keystore = getKeyStore("KeyStore-seconf", password);
		try {
			return SecureClient.getSymmetricKey(keystore, alias, password);
		} catch (Exception e) {
			return null;
		}
	}
	
	public KeyStore getKeyStore(String fileName, char[] passwd) {
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
	
	private byte[] makeSignature(byte[] data) throws Exception{
		String _alias = "client";
		char[] _password = "seconf".toCharArray();
		KeyStore _ks = getKeyStore("KeyStore-seconf", _password);
		return SecureClient.makeSignature(_ks, _alias, _password, data);
	}
	
	private String getBodyElement(SOAPMessageContext smc, String tag) {
		try {
			// get SOAP envelope header
			SOAPMessage msg = smc.getMessage();
			SOAPPart sp = msg.getSOAPPart();
			SOAPEnvelope se = sp.getEnvelope();
			SOAPBody sh = se.getBody();
			return findAttributeRecursive2(sh, tag);
		} catch (Exception e) {
			System.out.println("Erro getHeaderElement");
		}
		return null;
	}
	
	private String findAttributeRecursive2(SOAPElement element, String tag) {
		NodeList nl = element.getChildNodes();
		for (int i = 0; i < nl.getLength(); i++) {
			if (nl.item(i).getNodeType() == Node.ELEMENT_NODE) {
				SOAPElement se = (SOAPElement) nl.item(i);
				if (se.getNodeName().equals(tag)) {
					return se.getValue();
				}
				String atr = findAttributeRecursive2(se, tag);
				if (atr != null) {
					return atr;
				}
			}
		}
		return null;
	}
}
