package pm.exception;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;


@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "InvalidPasswordException", propOrder = {
    "message"
})
public class InvalidPasswordException extends PasswordManagerException {
    private static final long serialVersionUID = 1L;

    private static final String message = "Invalid Key used";
    
    public InvalidPasswordException(String message){
        super(message);
    }
    public InvalidPasswordException(){
        super(message);
    }
}

