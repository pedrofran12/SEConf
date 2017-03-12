package pm.exception;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "UnknownUsernameDomainException", propOrder = {
    "message"
})
public class UnknownUsernameDomainException extends Exception {

    private static final long serialVersionUID = 1L;

    private static final String message = "Username or domain invalid";
    
    public UnknownUsernameDomainException(String mess){
        super(mess);
    }
    public UnknownUsernameDomainException(){
        super(message);
    }
}
