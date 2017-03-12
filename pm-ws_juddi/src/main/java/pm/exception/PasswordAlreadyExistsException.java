package pm.exception;

import javax.xml.bind.annotation.XmlAccessType;
import javax.xml.bind.annotation.XmlAccessorType;
import javax.xml.bind.annotation.XmlType;

@XmlAccessorType(XmlAccessType.FIELD)
@XmlType(name = "PasswordAlreadyExistsException", propOrder = {
    "message"
})
public class PasswordAlreadyExistsException extends Exception {

    private static final long serialVersionUID = 1L;

    private static final String message = "Password already exists.";
    
    public PasswordAlreadyExistsException(String mess){
        super(mess);
    }
    public PasswordAlreadyExistsException(){
        super(message);
    }
}