package pm.exception;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "InvalidMessageDigestException", propOrder = {
    "message"
})
public class InvalidMessageDigestException extends PasswordManagerException {
    private static final long serialVersionUID = 1L;

    private static final String message = "Invalid Message Digest used";
    
    public InvalidMessageDigestException(String message){
        super(message);
    }
    public InvalidMessageDigestException(){
        super(message);
    }
}

