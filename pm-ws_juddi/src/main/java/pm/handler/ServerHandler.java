package pm.handler;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.security.NoSuchAlgorithmException;
import java.sql.Timestamp;
import java.util.Base64;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Set;

import javax.xml.soap.*;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.*;

import org.apache.commons.net.ntp.NTPUDPClient;
import org.apache.commons.net.ntp.TimeInfo;
import org.w3c.dom.NodeList;

import static javax.xml.bind.DatatypeConverter.printHexBinary;
import static javax.xml.bind.DatatypeConverter.parseHexBinary;

public class ServerHandler implements SOAPHandler<SOAPMessageContext> {
    
    private HandlerSecurity _security;

    public static final String HEADER_DSIGN = "dsign";
    public static final String HEADER_DSIGN_NS = "urn:dsign";
    
    public static final String HEADER_NONCE = "nonce";
    public static final String HEADER_NONCE_NS = "urn:nonce";
    
    public static final String HEADER_TIMESTAMP = "timestamp";
    public static final String HEADER_TIMESTAMP_NS = "urn:timestamp";
    
    private static final int NONCE_TIMEOUT = 2*60*1000; //in milliseconds
    
    private HashMap<Integer, Long> nonceMap = new HashMap<Integer, Long>();

	public ServerHandler() throws NoSuchAlgorithmException, IOException {
		_security = new HandlerSecurity();
	}

	private HandlerSecurity getHandlerSecurity() {
		return _security;
	}

	@Override
	public boolean handleMessage(SOAPMessageContext smc) {
		Boolean outbound = (Boolean) smc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
		String operation = smc.get(MessageContext.WSDL_OPERATION).toString();
		System.out.println("\nOutbound = " + outbound);
		System.out.println("Method = " + operation);

		try {
			if (outbound) {
				final byte[] plainBytes = getMessage(smc).getBytes();

				// SEGURANCA : MAC
				HandlerSecurity security = getHandlerSecurity();

				// make MAC
				byte[] cipherDigest = security.makeSignature(plainBytes);
				addHeaderSM(smc, HEADER_DSIGN, HEADER_DSIGN_NS, printHexBinary(cipherDigest));

			} else { // message that is going to be sent from client to server
			    getMessage(smc); //required to program to work
			   	
				//Get MAC value
				String mac = getHeaderElement(smc, HEADER_DSIGN, HEADER_DSIGN_NS);

				//SOAP Message does not have MAC
				if (mac == null) {
					return false;
				}

				//Remove MAC from header
				SOAPHeader header = smc.getMessage().getSOAPPart().getEnvelope().getHeader();
				NodeList nl = header.getChildNodes();
				for (int i = 0; i < nl.getLength(); i++) {
					if (nl.item(i).getNodeName().equals("d:" + HEADER_DSIGN)) {
						header.removeChild(nl.item(i));
					}
				}
				header.normalize();

				//SOAP Message bytes without MAC
				final byte[] plainBytes = getMessage(smc).getBytes();

				//SEGURANCA : MAC
				HandlerSecurity security = getHandlerSecurity();

				//Client's Key
				byte[] byteElement = getBodyElement(smc, "key").getBytes();
				byte[] publicKeyClient = Base64.getDecoder().decode(byteElement);

				//Generate's MAC
				byte[] cipherDigest = parseHexBinary(mac);
				//Verify MAC
				boolean result = security.verifySignature(cipherDigest, plainBytes, publicKeyClient);
				System.out.println("DSIGN is " + (result ? "right" : "wrong"));
				if (!result) {
					return false;
				}
				
				//Verify Nonce+Timestamp
				int nonce = Integer.parseInt(getHeaderElement(smc, HEADER_NONCE ,HEADER_NONCE_NS)); //need to check with send 
                long ts = Long.parseLong(getHeaderElement(smc,HEADER_TIMESTAMP,HEADER_TIMESTAMP_NS));
                System.out.println("\nNonce = "+nonce);
                System.out.println("Timestamp = "+ts);
                
                if(!isNonceValid(nonce,ts)) //if nonce not valid returns false! (discards message)
                    return false;
			}

		} catch (Exception e) {
			System.out.print("Caught exception in handleMessage: ");
			System.out.println(e);
			System.out.println("Continue normal processing...");
			// e.printStackTrace();
		}
		System.out.println(getMessage(smc));
		System.out.println("\n\n================================================\n");
		System.out.println(String.format("%"+10+"s", "").replace(" ", "="));
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
        else if (nonceMap.containsKey(nonce) && (nonceMap.get(nonce) == nTs) ) {
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
        for(int j : nonceMap.keySet()){
            if(!compareTime(timeGenerated,nonceMap.get(j),NONCE_TIMEOUT))
                nonceMap.remove(j);
        }
    }
    
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

}
