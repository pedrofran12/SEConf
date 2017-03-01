package pm.exception;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "InvalidKeyException", propOrder = {
    "message"
})
public class InvalidKeyException extends PasswordManagerException {
    private static final long serialVersionUID = 1L;

    private static final String message = "Invalid Key used";
    
    public InvalidKeyException(String message){
        super(message);
    }
    public InvalidKeyException(){
        super(message);
    }
}

