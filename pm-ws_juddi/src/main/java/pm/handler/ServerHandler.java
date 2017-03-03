package pm.handler;

import java.io.ByteArrayOutputStream;
import java.util.Set;
import javax.xml.namespace.QName;
import javax.xml.soap.SOAPMessage;
import javax.xml.ws.handler.MessageContext;
import javax.xml.ws.handler.soap.SOAPHandler;
import javax.xml.ws.handler.soap.SOAPMessageContext;

public class ServerHandler implements SOAPHandler<SOAPMessageContext> {

	@Override
	public boolean handleMessage(SOAPMessageContext smc) {
        Boolean outbound = (Boolean) smc.get(MessageContext.MESSAGE_OUTBOUND_PROPERTY);
        String operation = smc.get(MessageContext.WSDL_OPERATION).toString();
        System.out.println("Outbound = " + outbound + "\n\n\n\n");
        System.out.println("Method = " + operation + "\n\n\n\n");
        try{
        	int i;
        }
        catch(Exception e){
        	
        }
        
		System.out.println(getMessage(smc));
		
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
     * Check the MESSAGE_OUTBOUND_PROPERTY in the context
     * to see if this is an outgoing or incoming message.
     * Write a brief message to the print stream and
     * output the message. The writeTo() method can throw
     * SOAPException or IOException
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


}