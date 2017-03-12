package pm.exception;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "InvalidDomainException", propOrder = {
    "message"
})
public class InvalidDomainException extends Exception {

    private static final long serialVersionUID = 1L;

    private static final String message = "Invalid Domain";
    
    public InvalidDomainException(String mess){
        super(mess);
    }
    public InvalidDomainException(){
        super(message);
    }
}